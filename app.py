from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
import os
import hashlib
import uuid
import requests
import time
import jwt
from datetime import timedelta, datetime, timezone
from ddgs import DDGS
from supabase import create_client, Client

# Email OTP (xato bo'lsa sayt yiqilmaydi, lekin Render logida ko'rinadi)
try:
    from email_auth import init_email_auth
except Exception as e:
    init_email_auth = None
    print("EMAIL_AUTH import xatosi:", repr(e), flush=True)

app = Flask(__name__)

# ==========================================
# SOZLAMALAR
# ==========================================
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

ADMIN_HASH = os.environ.get("ADMIN_HASH", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET Render Environment'da sozlanmagan yoki juda qisqa!")

secret = os.environ.get("FLASK_SECRET_KEY")
if not secret or len(secret) < 32:
    raise RuntimeError("FLASK_SECRET_KEY Render Environment'da sozlanmagan yoki juda qisqa!")

app.secret_key = secret
app.config.update(
    SESSION_COOKIE_NAME="blip_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

CORS(
    app,
    origins=["https://dasturchi-top-1.github.io"],
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

# ==========================================
# OAUTH KONFIGURATSIYASI
# ==========================================
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# ==========================================
# YORDAMCHI FUNKSIYALAR
# ==========================================
def create_jwt(user_id, role):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": str(role),
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "iss": "blip-multiverse"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_jwt_payload():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(
            auth[7:].strip(), JWT_SECRET,
            algorithms=["HS256"],
            issuer="blip-multiverse"
        )
    except jwt.InvalidTokenError:
        return None


def check_auth():
    """Strict auth: Authorization mavjud bo'lsa faqat JWT, yo'q bo'lsa session."""
    auth_present = "Authorization" in request.headers
    auth_header = request.headers.get("Authorization", "").strip()

    if auth_present:
        if not auth_header:
            return False, None, (
                jsonify({"error": "Invalid authorization header"}), 401
            )

        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False, None, (
                jsonify({"error": "Invalid authorization header"}), 401
            )

        payload = get_jwt_payload()
        if not payload or not payload.get("sub"):
            return False, None, (
                jsonify({"error": "Invalid or expired token"}), 401
            )

        return True, payload["sub"], None

    session_user = session.get("user_id")
    if not session_user:
        return False, None, (
            jsonify({"error": "Authentication required"}), 401
        )

    return True, str(session_user), None


def make_request_with_retry(url, headers, json_data, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=json_data, timeout=30)
            if response.status_code in [200, 201]:
                return response
            if response.status_code in [503, 429]:
                time.sleep(2 ** attempt)
                continue
            return response
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return response

# ==========================================
# ASOSIY ROUTE'LAR
# ==========================================
@app.route('/')
def home():
    status = "Supabase ulangan OK" if supabase else "Supabase ULANMAGAN"
    oauth_status = "OAuth tayyor" if os.environ.get("GOOGLE_CLIENT_ID") else "OAuth sozlanmagan"
    return f"Blip Flask Backend ishlayapti! ({status}) ({oauth_status})"

@app.route('/api/register', methods=['POST'])
def register():
    return jsonify({"error": "Ro'yxatdan o'tish faqat Google yoki GitHub orqali."}), 410
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password: return jsonify({"error": "Ism va parol kerak"}), 400
    if len(username) < 3: return jsonify({"error": "Ism kamida 3 harf"}), 400
    if not supabase: return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        existing = supabase.table("users").select("id").eq("username", username).execute()
        if existing.data and len(existing.data) > 0:
            return jsonify({"error": "Bu ism band!"}), 400
        hashed = hashlib.sha256(password.encode()).hexdigest()
        supabase.table("users").insert({"username": username, "password_hash": hashed, "role": "human"}).execute()
        return jsonify({"success": True, "message": "Ro'yxatdan o'tdingiz!"})
    except Exception as e:
        return jsonify({"error": f"Baza xatosi: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password: return jsonify({"error": "Ism va parolni kiriting"}), 400
    hashed = hashlib.sha256(password.encode()).hexdigest()

    # Admin
    if username == "admin" and hashed == ADMIN_HASH:
        token = create_jwt("admin", "admin")
        return jsonify({
            "success": True,
            "token": token,
            "role": "admin",
            "redirect": "multiverse.html"
        })

    # Oddiy foydalanuvchilar uchun parol bilan kirish o'chirilgan
    return jsonify({"error": "Parol bilan kirish faqat admin uchun. Google yoki GitHub orqali kiring."}), 403

    if not supabase: return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        result = supabase.table("users").select("*").eq("username", username).execute()
        if result.data and len(result.data) > 0:
            user = result.data[0]
            if not user.get("password_hash"):
                return jsonify({"error": "OAuth orqali yaratilgan. Google yoki GitHub bilan kiring."}), 401
            if user["password_hash"] == hashed:
                role = user.get("role", "human")
                token = create_jwt(user["id"], role)
                return jsonify({
                    "success": True,
                    "token": token,
                    "role": role,
                    "redirect": "multiverse.html"
                })
        return jsonify({"error": "Ism yoki parol xato!"}), 401
    except Exception as e:
        return jsonify({"error": f"Baza xatosi: {str(e)}"}), 500

@app.route("/api/me", methods=["GET"])
def current_user():
    auth_present = "Authorization" in request.headers
    auth_header = request.headers.get("Authorization", "").strip()

    # 1. Authorization mavjud — FAQAT JWT (session bypass YO'Q)
    if auth_present:
        if not auth_header:
            return jsonify({"success": False, "authenticated": False}), 401

        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"success": False, "authenticated": False}), 401

        payload = get_jwt_payload()
        if not payload or not payload.get("sub"):
            return jsonify({"success": False, "authenticated": False}), 401

        user_id = payload.get("sub")
        role = payload.get("role")

        if str(user_id) == "admin":
            if role != "admin":
                return jsonify({"success": False, "authenticated": False}), 401
            return jsonify({
                "success": True, "authenticated": True,
                "role": "admin", "username": "Admin"
            })

        if not supabase:
            return jsonify({"error": "Baza ulanmagan"}), 500

        try:
            result = supabase.table("users").select("id, username, role").eq("id", user_id).execute()
            if not result.data:
                return jsonify({"success": False, "authenticated": False}), 401
            user = result.data[0]
            if user.get("role", "human") != role:
                return jsonify({"success": False, "authenticated": False}), 401
            return jsonify({
                "success": True, "authenticated": True,
                "user_id": user["id"], "username": user["username"],
                "role": user.get("role", "human")
            })
        except Exception:
            return jsonify({"error": "Server xatosi"}), 500

    # 2. Authorization umuman yo'q — session (OAuth)
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "authenticated": False}), 401

    if user_id == "admin" and session.get("role") == "admin":
        return jsonify({
            "success": True, "authenticated": True,
            "role": "admin", "username": "Admin"
        })

    if not supabase:
        return jsonify({"error": "Baza ulanmagan"}), 500

    try:
        result = supabase.table("users").select("id, username, role").eq("id", user_id).execute()
        if not result.data:
            session.clear()
            return jsonify({"success": False, "authenticated": False}), 401
        user = result.data[0]
        return jsonify({
            "success": True, "authenticated": True,
            "user_id": user["id"], "username": user["username"],
            "role": user.get("role", "human")
        })
    except Exception:
        return jsonify({"error": "Server xatosi"}), 500
        @app.route('/api/verify-token', methods=['POST'])
def verify_token():
    # AI uchun session (o'zgarmagan)
    user_id = session.get("user_id")
    if not user_id: return jsonify({"valid": False}), 401
    if user_id == "admin" and session.get("role") == "admin":
        return jsonify({"valid": True, "role": "admin"})
    try:
        result = supabase.table("users").select("role").eq("id", user_id).execute()
        if not result.data:
            session.clear()
            return jsonify({"valid": False}), 401
        return jsonify({"valid": True, "role": result.data[0].get("role", "human")})
    except Exception:
        return jsonify({"valid": False}), 500

@app.route('/api/admin/stats', methods=['POST'])
def admin_stats():
    payload = get_jwt_payload()
    if payload is None:
        return jsonify({"error": "Authentication required"}), 401
    if str(payload.get("sub")) != "admin" or payload.get("role") != "admin":
        return jsonify({"error": "Admin huquqi yo'q"}), 403
    if not supabase:
        return jsonify({"error": "Baza ulanmagan"}), 500
    try:
        result = supabase.table("users").select("username").execute()
        users_list = [u["username"] for u in result.data] if result.data else []
        return jsonify({"success": True, "total_users": len(users_list), "users": users_list})
    except Exception:
        return jsonify({"error": "Statistika olinmadi"}), 500

# ==========================================
# AI CHAT (strict auth + JSON validation)
# ==========================================
@app.route('/api/chat', methods=['POST'])
def chat():
    ok, user_id, err = check_auth()
    if not ok:
        return err

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    message = data.get('message')
    if not message or not isinstance(message, str):
        return jsonify({"error": "Message required"}), 400

    sys_prompt = data.get('systemPrompt', 'Sen foydali AI yordamchisan.')

    if OPENROUTER_API_KEY:
        try:
            payload = {"model": "nvidia/nemotron-3.5-super-vl:free", "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": message}]}
            headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
            response = make_request_with_retry("https://openrouter.ai/api/v1/chat/completions", headers, payload)
            if response.status_code == 200:
                reply = response.json()['choices'][0]['message']['content']
                return jsonify({"success": True, "reply": reply, "provider": "OpenRouter"})
        except Exception as e:
            print(f"OpenRouter xatosi: {e}")

    if GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
            payload = {"contents": [{"role": "user", "parts": [{"text": message}]}], "systemInstruction": {"parts": [{"text": sys_prompt}]}}
            response = make_request_with_retry(url, {}, payload)
            if response.status_code == 200:
                reply = response.json()['candidates'][0]['content']['parts'][0]['text']
                return jsonify({"success": True, "reply": reply, "provider": "Gemini"})
            else:
                return jsonify({"error": f"Gemini: {response.status_code}"}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "AI kalitlari ishlamayapti"}), 500

@app.route('/api/ai-login', methods=['POST'])
def ai_login():
    # AI imtihon (session, o'zgarmagan)
    data = request.json
    answers = data.get('answers', [])
    if len(answers) < 30: return jsonify({"error": "30 ta savolga javob bering"}), 400
    prompt = f"Sen imtihon tekshiruvchisisan. AI 30 ta savolga javob berdi: {answers}. Agar mantiqan to'g'ri bo'lsa 'PASS', aks holda 'FAIL' deb yoz."
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    try:
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        response = make_request_with_retry(url, {}, payload)
        result = response.json()['candidates'][0]['content']['parts'][0]['text'].strip().upper()
        if result == "PASS":
            session.clear()
            session["user_id"] = "ai_node"
            session["role"] = "ai"
            session.permanent = True
            return jsonify({"success": True, "redirect": "ai_multiverse.html"})
        return jsonify({"error": "Javoblar yetarli emas."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# QIDIRUV (strict auth)
# ==========================================
@app.route('/api/search', methods=['GET'])
def search():
    ok, user_id, err = check_auth()
    if not ok:
        return err

    query = request.args.get("q", "").strip()
    if len(query) < 2: return jsonify({"success": False, "error": "Kamida 2 ta belgi kiriting."}), 400
    if len(query) > 200: return jsonify({"success": False, "error": "Juda uzun."}), 400
    try:
        with DDGS() as ddgs:
            raw_results = ddgs.text(query, max_results=10)
            results = [{"title": item.get("title", ""), "url": item.get("href", ""), "snippet": item.get("body", "")} for item in raw_results]
        return jsonify({"success": True, "query": query, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 502

# ==========================================
# OAUTH YORDAMCHI FUNKSIYASI
# ==========================================
def handle_oauth_login(name, email, provider, provider_user_id, email_verified=False):
    if not supabase:
        return "Database unavailable", 500
    if provider not in ("google", "github"):
        return "Unsupported provider", 400
    if not provider_user_id:
        return "OAuth provider ID missing", 400
    if provider == "google" and (not email or not email_verified):
        return "Google email is not verified", 403

    try:
        identity_result = (
            supabase.table("auth_identities")
            .select("user_id")
            .eq("provider", provider)
            .eq("provider_user_id", str(provider_user_id))
            .execute()
        )

        if identity_result.data:
            user_id = identity_result.data[0]["user_id"]
            user_result = supabase.table("users").select("id, username, role").eq("id", user_id).execute()
            if not user_result.data:
                return "User account not found", 404
            user = user_result.data[0]
        else:
            base = "".join(char.lower() if char.isalnum() else "_" for char in (name or "user")).strip("_") or "user"
            username = base
            suffix = 1
            while True:
                existing = supabase.table("users").select("id").eq("username", username).execute()
                if not existing.data:
                    break
                suffix += 1
                username = f"{base}_{suffix}"

            created = supabase.table("users").insert({
                "username": username,
                "password_hash": None,
                "email": email,
                "email_verified": bool(email_verified),
                "role": "human"
            }).execute()

            if not created.data:
                return "Could not create user", 500
            user = created.data[0]

            supabase.table("auth_identities").insert({
                "user_id": user["id"],
                "provider": provider,
                "provider_user_id": str(provider_user_id)
            }).execute()

        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user.get("role", "human")
        session.permanent = True

        return redirect("https://dasturchi-top-1.github.io/Dasturchi-top-1/multiverse.html")
    except Exception:
        app.logger.exception("OAuth login failed")
        return "OAuth login failed", 500

# ==========================================
# GOOGLE OAUTH
# ==========================================
@app.route("/api/auth/google")
def auth_google():
    if not os.environ.get("GOOGLE_CLIENT_ID") or not os.environ.get("GOOGLE_CLIENT_SECRET"):
        return "Google OAuth sozlanmagan", 503
    redirect_uri = url_for("auth_google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/api/auth/google/callback")
def auth_google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")
        if not user_info:
            try:
                user_info = google.parse_id_token(token, None)
            except Exception:
                user_info = None
        if not user_info:
            return "Google user information missing", 400
        email = user_info.get("email")
        name = user_info.get("name") or (email.split("@")[0] if email else "Google User")
        provider_user_id = user_info.get("sub")
        email_verified = user_info.get("email_verified", False)
        return handle_oauth_login(
            name=name, email=email, provider="google",
            provider_user_id=provider_user_id, email_verified=email_verified
        )
    except Exception:
        app.logger.exception("Google callback failed")
        return "Google login failed", 500

# ==========================================
# GITHUB OAUTH
# ==========================================
@app.route("/api/auth/github")
def auth_github():
    if not os.environ.get("GITHUB_CLIENT_ID") or not os.environ.get("GITHUB_CLIENT_SECRET"):
        return "GitHub OAuth sozlanmagan", 503
    redirect_uri = url_for("auth_github_callback", _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route("/api/auth/github/callback")
def auth_github_callback():
    try:
        github.authorize_access_token()
        profile_response = github.get("user")
        profile_response.raise_for_status()
        profile = profile_response.json()
        provider_user_id = profile.get("id")
        name = profile.get("login") or profile.get("name") or "GitHub User"
        if not provider_user_id:
            return "GitHub user ID missing", 400

        emails_response = github.get("user/emails")
        emails_response.raise_for_status()
        emails = emails_response.json()
        primary = next((item for item in emails if item.get("primary") and item.get("verified")), None)
        email = primary.get("email") if primary else None
        email_verified = bool(primary)
        return handle_oauth_login(
            name=name, email=email, provider="github",
            provider_user_id=str(provider_user_id), email_verified=email_verified
        )
    except Exception:
        app.logger.exception("GitHub callback failed")
        return "GitHub login failed", 500

# ==========================================
# EMAIL OTP (6 xonali kod bilan kirish)
# ==========================================
if init_email_auth is not None and supabase is not None:
    init_email_auth(app, supabase, create_jwt, JWT_SECRET)
else:
    print("EMAIL_AUTH ulanmadi (modul yoki Supabase yo'q)", flush=True)

# ==========================================
# SERVERNI ISHGA TUSHIRISH
# ==========================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
