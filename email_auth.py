import os
import re
import hmac
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, request, jsonify


email_auth = Blueprint("email_auth", __name__)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$"
)
CODE_RE = re.compile(r"^\d{6}$")

OTP_TTL = 600
MAX_ATTEMPTS = 5
RESEND_SECONDS = 60


def send_email_code(email, code):
    api_key = os.getenv("BREVO_API_KEY")
    sender = os.getenv("MAIL_SENDER")

    if not api_key or not sender:
        raise RuntimeError("Brevo sozlamalari mavjud emas")

    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": api_key,
            "accept": "application/json",
            "content-type": "application/json",
        },
        json={
            "sender": {
                "name": "Black AI",
                "email": sender,
            },
            "to": [{"email": email}],
            "subject": "Black AI — tasdiqlash kodi",
            "htmlContent": f"""
                <div style="font-family:Arial;padding:24px">
                    <h2>Black AI</h2>
                    <p>Kirish kodingiz:</p>
                    <h1 style="letter-spacing:8px">{code}</h1>
                    <p>Kod 10 daqiqa amal qiladi.</p>
                    <p>Ushbu kodni hech kimga bermang.</p>
                </div>
            """,
        },
        timeout=15,
    )

    if response.status_code not in (200, 201, 202):
        logging.error("Brevo xatosi: %s", response.status_code)
        raise RuntimeError("Email yuborilmadi")


def make_code_hash(secret, email, code):
    message = f"{email}:{code}".encode()
    return hmac.new(
        secret.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()


def init_email_auth(app, supabase, create_jwt, jwt_secret):
    if not jwt_secret:
        raise RuntimeError("JWT_SECRET mavjud emas")

    secret = hashlib.sha256(
        ("black-ai-email:" + jwt_secret).encode()
    ).hexdigest()

    @email_auth.post("/api/auth/email/request")
    def request_email_code():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()

        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            return jsonify({
                "success": False,
                "error": "Email manzili noto'g'ri",
            }), 400

        try:
            now = datetime.now(timezone.utc)

            recent = (
                supabase.table("email_otps")
                .select("created_at")
                .eq("email", email)
                .gte(
                    "created_at",
                    (now - timedelta(hours=1)).isoformat(),
                )
                .order("created_at", desc=True)
                .execute()
            ).data or []

            if len(recent) >= 5:
                return jsonify({
                    "success": False,
                    "error": "Soatlik limit tugadi",
                }), 429

            if recent:
                last = datetime.fromisoformat(
                    recent[0]["created_at"].replace(
                        "Z", "+00:00"
                    )
                )

                if (now - last).total_seconds() < RESEND_SECONDS:
                    return jsonify({
                        "success": False,
                        "error": "Qayta yuborish uchun kuting",
                    }), 429

            code = f"{secrets.randbelow(1000000):06d}"

            # Oldingi kodlarni bekor qilish
            (
                supabase.table("email_otps")
                .update({"used": True})
                .eq("email", email)
                .eq("used", False)
                .execute()
            )

            result = (
                supabase.table("email_otps")
                .insert({
                    "email": email,
                    "code_hash": make_code_hash(
                        secret, email, code
                    ),
                    "attempts": 0,
                    "used": False,
                    "expires_at": (
                        now + timedelta(seconds=OTP_TTL)
                    ).isoformat(),
                })
                .execute()
            )

            if not result.data:
                raise RuntimeError("Kod saqlanmadi")

            otp_id = result.data[0]["id"]

            try:
                send_email_code(email, code)
            except Exception:
                (
                    supabase.table("email_otps")
                    .update({"used": True})
                    .eq("id", otp_id)
                    .execute()
                )
                raise

            return jsonify({
                "success": True,
                "message": "Tasdiqlash kodi yuborildi",
                "expires_in": OTP_TTL,
                "resend_in": RESEND_SECONDS,
            })

        except Exception:
            app.logger.exception("Email kod yuborish xatosi")
            return jsonify({
                "success": False,
                "error": "Email yuborishda xatolik",
            }), 502
            @email_auth.post("/api/auth/email/verify")
    def verify_email_code():
        data = request.get_json(silent=True) or {}

        email = str(data.get("email", "")).strip().lower()
        code = str(data.get("code", "")).strip()

        if (
            len(email) > 254
            or not EMAIL_RE.fullmatch(email)
            or not CODE_RE.fullmatch(code)
        ):
            return jsonify({
                "success": False,
                "error": "Email yoki kod noto'g'ri",
            }), 400

        try:
            now = datetime.now(timezone.utc)

            rows = (
                supabase.table("email_otps")
                .select("*")
                .eq("email", email)
                .eq("used", False)
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            ).data or []

            if not rows:
                return jsonify({
                    "success": False,
                    "error": "Kod noto'g'ri yoki muddati tugagan",
                }), 400

            otp = rows[0]

            expires = datetime.fromisoformat(
                otp["expires_at"].replace("Z", "+00:00")
            )

            if now > expires or otp["attempts"] >= MAX_ATTEMPTS:
                (
                    supabase.table("email_otps")
                    .update({"used": True})
                    .eq("id", otp["id"])
                    .eq("used", False)
                    .execute()
                )

                return jsonify({
                    "success": False,
                    "error": "Kod muddati tugagan",
                }), 400

            # Urinishni OLDINDAN yozamiz. Bir vaqtda kelgan ko'p so'rov
            # bir xil hisoblagichni o'qib, limitni aylanib o'tmasligi uchun.
            bumped = (
                supabase.table("email_otps")
                .update({"attempts": otp["attempts"] + 1})
                .eq("id", otp["id"])
                .eq("attempts", otp["attempts"])
                .execute()
            ).data or []

            if not bumped:
                return jsonify({
                    "success": False,
                    "error": "Tasdiqlash kodi noto'g'ri",
                }), 400

            expected = make_code_hash(secret, email, code)

            if not hmac.compare_digest(otp["code_hash"], expected):
                return jsonify({
                    "success": False,
                    "error": "Tasdiqlash kodi noto'g'ri",
                }), 400

            # Kodni ishlatilgan deb belgilash
            claimed = (
                supabase.table("email_otps")
                .update({"used": True})
                .eq("id", otp["id"])
                .eq("used", False)
                .execute()
            ).data or []

            if not claimed:
                return jsonify({
                    "success": False,
                    "error": "Kod allaqachon ishlatilgan",
                }), 400

            # Faqat emaili aniq tasdiqlangan hisobni topamiz.
            users = (
                supabase.table("users")
                .select("id,username,role,email_verified")
                .eq("email", email)
                .limit(2)
                .execute()
            ).data or []

            if len(users) > 1:
                return jsonify({
                    "success": False,
                    "error": "Hisobni qo'lda tekshirish kerak",
                }), 409

            if users:
                user = users[0]

                # Mavjud, ammo tasdiqlanmagan hisobni
                # avtomatik egallashga yo'l qo'ymaymiz.
                if not user.get("email_verified"):
                    return jsonify({
                        "success": False,
                        "error": "Hisob emaili hali tasdiqlanmagan",
                    }), 403

            else:
                # OAuth hisoblarini email bo'yicha avtomatik
                # bog'lamaymiz. Yangi email hisobi yaratiladi.
                base = re.sub(
                    r"[^a-z0-9]+",
                    "_",
                    email.split("@")[0].lower(),
                ).strip("_")[:20] or "user"

                username = f"{base}_{secrets.token_hex(3)}"

                created = (
                    supabase.table("users")
                    .insert({
                        "username": username,
                        "password_hash": None,
                        "email": email,
                        "email_verified": True,
                        "role": "human",
                    })
                    .execute()
                ).data or []

                if not created:
                    raise RuntimeError("Foydalanuvchi yaratilmadi")

                user = created[0]

            token = create_jwt(
                user["id"],
                user.get("role") or "human",
            )

            return jsonify({
                "success": True,
                "token": token,
                "role": user.get("role") or "human",
                "redirect": "multiverse.html",
            })

        except Exception:
            app.logger.exception("Email tasdiqlash xatosi")
            return jsonify({
                "success": False,
                "error": "Server xatosi",
            }), 500

    app.register_blueprint(email_auth)
