import hashlib
import hmac
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, jsonify, request


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@"
    r"[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$"
)
CODE_RE = re.compile(r"^\d{6}$")

CODE_TTL = 600
MAX_ATTEMPTS = 5
RESEND_COOLDOWN = 60
MAX_EMAIL_PER_HOUR = 5

IP_REQUEST_LIMIT = 20
IP_VERIFY_LIMIT = 30

_hits = defaultdict(deque)


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


def client_ip():
    # Reverse proxy sozlamasi tekshirilmaguncha
    # X-Forwarded-For qiymatiga ishonmaymiz.
    return request.remote_addr or "unknown"


def rate_allowed(key, limit, window):
    now = time.monotonic()
    hits = _hits[key]

    while hits and now - hits[0] > window:
        hits.popleft()

    if len(hits) >= limit:
        return False

    hits.append(now)
    return True


def hash_code(secret_key, email, code):
    message = f"{email}:{code}".encode("utf-8")

    return hmac.new(
        secret_key,
        message,
        hashlib.sha256
    ).hexdigest()


def send_code_email(to_email, code):
    api_key = os.environ.get("BREVO_API_KEY")
    sender = os.environ.get("MAIL_SENDER")

    if not api_key or not sender:
        raise RuntimeError("Brevo sozlanmagan")

    html = f"""
    <div style="font-family:Arial;padding:25px;
                background:#0b0b1a;color:white">
        <h2>Black AI</h2>
        <p>Kirish uchun tasdiqlash kodingiz:</p>
        <h1 style="letter-spacing:8px;color:#a5b4fc">
            {code}
        </h1>
        <p>Kod 10 daqiqa amal qiladi.</p>
        <p>Kodni hech kimga bermang.</p>
    </div>
    """

    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": api_key,
            "accept": "application/json",
            "content-type": "application/json"
        },
        json={
            "sender": {
                "name": "Black AI",
                "email": sender
            },
            "to": [{"email": to_email}],
            "subject": "Black AI — tasdiqlash kodi",
            "htmlContent": html
        },
        timeout=15
    )

    if response.status_code not in (200, 201, 202):
        raise RuntimeError(
            f"Brevo xatosi: {response.status_code}"
        )


def make_username(supabase, email):
    base = re.sub(
        r"[^a-z0-9]+",
        "_",
        email.split("@")[0].lower()
    ).strip("_")[:20] or "user"

    for _ in range(30):
        suffix = secrets.token_hex(3)
        username = f"{base}_{suffix}"

        result = (
            supabase.table("users")
            .select("id")
            .eq("username", username)
            .limit(1)
            .execute()
        )

        if not result.data:
            return username

    raise RuntimeError("Username yaratilmadi")


def init_email_auth(
    app,
    supabase,
    create_jwt,
    jwt_secret,
    send_func=None
):
    if not jwt_secret:
        raise RuntimeError("JWT_SECRET mavjud emas")

    blueprint = Blueprint("email_auth", __name__)

    send = send_func or send_code_email

    hmac_key = hashlib.sha256(
        b"black-ai-email-otp:" + jwt_secret.encode()
    ).digest()

    def error(message, status=400):
        return jsonify({
            "success": False,
            "error": message
        }), status

    def get_data():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    @blueprint.route(
        "/api/auth/email/request",
        methods=["POST"]
    )
    def email_request():
        if not supabase:
            return error("Database ulanmagan", 500)

        data = get_data()
        email = str(data.get("email", "")).strip().lower()

        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            return error("Email manzilini tekshiring")

        ip = client_ip()

        if not rate_allowed(
            ("request", ip), IP_REQUEST_LIMIT, 600
        ):
            return error("Juda ko'p so'rov. Keyinroq urinib ko'ring.", 429)

        try:
            now = now_utc()

            recent = (
                supabase.table("email_otps")
                .select("created_at")
                .eq("email", email)
                .gte(
                    "created_at",
                    iso(now - timedelta(hours=1))
                )
                .order("created_at", desc=True)
                .execute()
            ).data or []

            if len(recent) >= MAX_EMAIL_PER_HOUR:
                return error("Soatlik limit tugadi.", 429)

            if recent:
                last = datetime.fromisoformat(
                    recent[0]["created_at"].replace(
                        "Z", "+00:00"
                    )
                )

                remaining = (
                    RESEND_COOLDOWN -
                    (now - last).total_seconds()
                )

                if remaining > 0:
                    return jsonify({
                        "success": False,
                        "error": "Qayta yuborishdan oldin kuting.",
                        "retry_after": int(remaining) + 1
                    }), 429

            code = f"{secrets.randbelow(1000000):06d}"

            # Avvalgi faol kodni bekor qilish.
            (
                supabase.table("email_otps")
                .update({"used": True})
                .eq("email", email)
                .eq("used", False)
                .execute()
            )

            inserted = (
                supabase.table("email_otps")
                .insert({
                    "email": email,
                    "code_hash": hash_code(
                        hmac_key, email, code
                    ),
                    "attempts": 0,
                    "used": False,
                    "expires_at": iso(
                        now + timedelta(seconds=CODE_TTL)
                    )
                })
                .execute()
            )

            if not inserted.data:
                raise RuntimeError("OTP saqlanmadi")

            otp_id = inserted.data[0]["id"]

            try:
                send(email, code)
            except Exception:
                (
                    supabase.table("email_otps")
                    .update({"used": True})
                    .eq("id", otp_id)
                    .execute()
                )
                app.logger.exception("Brevo email xatosi")
                return error("Email yuborilmadi.", 502)

            return jsonify({
                "success": True,
                "message": "Agar email to'g'ri bo'lsa, kod yuborildi.",
                "expires_in": CODE_TTL,
                "resend_in": RESEND_COOLDOWN
            })

        except Exception:
            app.logger.exception("Email request xatosi")
            return error("Server xatosi", 500)

    @blueprint.route(
        "/api/auth/email/verify",
        methods=["POST"]
    )
    def email_verify():
        if not supabase:
            return error("Database ulanmagan", 500)

        data = get_data()

        email = str(data.get("email", "")).strip().lower()
        code = str(data.get("code", "")).strip()

        if (
            len(email) > 254
            or not EMAIL_RE.fullmatch(email)
            or not CODE_RE.fullmatch(code)
        ):
            return error("Email yoki kod noto'g'ri")

        ip = client_ip()

        if not rate_allowed(
            ("verify", ip), IP_VERIFY_LIMIT, 600
        ):
            return error("Juda ko'p urinish.", 429)

        try:
            now = now_utc()

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
                return error("Kod noto'g'ri yoki muddati o'tgan")

            otp = rows[0]

            expires = datetime.fromisoformat(
                otp["expires_at"].replace("Z", "+00:00")
            )

            if (
                now > expires
                or otp["attempts"] >= MAX_ATTEMPTS
            ):
                (
                    supabase.table("email_otps")
                    .update({"used": True})
                    .eq("id", otp["id"])
                    .execute()
                )

                return error("Kod noto'g'ri yoki muddati o'tgan")

            expected = hash_code(
                hmac_key, email, code
            )

            if not hmac.compare_digest(
                otp["code_hash"], expected
            ):
                (
                    supabase.table("email_otps")
                    .update({
                        "attempts": otp["attempts"] + 1
                    })
                    .eq("id", otp["id"])
                    .execute()
                )

                return error("Kod noto'g'ri yoki muddati o'tgan")

            # Bu oddiy REST ketma-ketligi parallel so'rovlarga
            # qarshi to'liq atomik emas. Productiondan oldin
            # Supabase RPC orqali atomik tekshiruvga almashtiriladi.
            claimed = (
                supabase.table("email_otps")
                .update({"used": True})
                .eq("id", otp["id"])
                .eq("used", False)
                .select("id")
                .execute()
            ).data

            if not claimed:
                return error("Kod allaqachon ishlatilgan")

            found = (
                supabase.table("users")
                .select("id,username,role,email_verified")
                .eq("email", email)
                .limit(2)
                .execute()
            ).data or []

            if len(found) > 1:
                app.logger.error(
                    "Bir email bir nechta hisobga bog'langan"
                )
                return error("Hisobni tekshirish kerak.", 409)

            is_new = not found

            if found:
                user = found[0]

                if not user.get("email_verified"):
                    (
                        supabase.table("users")
                        .update({"email_verified": True})
                        .eq("id", user["id"])
                        .execute()
                    )

            else:
                created = (
                    supabase.table("users")
                    .insert({
                        "username": make_username(
                            supabase, email
                        ),
                        "password_hash": None,
                        "email": email,
                        "email_verified": True,
                        "role": "human"
                    })
                    .execute()
                )

                if not created.data:
                    return error("Hisob yaratilmadi", 500)

                user = created.data[0]

            role = user.get("role") or "human"

            token = create_jwt(user["id"], role)

            return jsonify({
                "success": True,
                "token": token,
                "role": role,
                "redirect": "multiverse.html",
                "is_new": is_new
            })

        except Exception:
            app.logger.exception("Email verify xatosi")
            return error("Server xatosi", 500)

    app.register_blueprint(blueprint)
