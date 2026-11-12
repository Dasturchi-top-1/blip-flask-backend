from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
import os
import hashlib
import time
import requests
import jwt
from datetime import timedelta, datetime, timezone
from ddgs import DDGS
from supabase import create_client, Client

# Email OTP blueprint
try:
    from email_auth import init_email_auth
except ImportError:
    init_email_auth = None

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
            auth[7:].strip(),
            JWT_SECRET,
            algorithms=["HS256"],
            issuer="blip-multiverse"
        )
    except jwt.InvalidTokenError:
        return None

def check_auth():
    """Strict: Authorization bo'lsa faqat JWT, bo'lmasa session."""
    auth_present = "Authorization" in request.headers
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_present:
        if not auth_header:
            return False, None, (jsonify({"error": "Invalid authorization header"}), 401)
        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False, None, (jsonify({"error": "Invalid authorization header"}), 401)
        payload = get_jwt_payload()
        if not payload or not payload.get("sub"):
            return False, None, (jsonify({"error": "Invalid or expired token"}), 401)
        return True, payload["sub"], None

    session_user = session.get("user_id")
    if not session_user:
        return False, None, (jsonify({"error": "Authentication required"}), 401)
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
        except Exception:
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
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({"error": "Ism va parol kerak"}), 400
    if len(username) < 3:
        return jsonify({"error": "Ism kamida 3 harf"}), 400
    if not supabase:
        return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        existing = supabase.table("users").select("id").eq("username", username).execute()
        if existing.data and len(existing.data) > 0:
            return jsonify({"error": "Bu ism band!"}), 400
        hashed = hashlib.sha256(password.encode()).hexdigest()
        supabase.table("users").insert({
            "username": username,
            "password_hash": hashed,
            "role": "human"
        }).execute()
        return jsonify({"success": True, "message": "Ro'yxatdan o'tdingiz!"})
    except Exception as e:
        return jsonify({"error": f"Baza xatosi: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({"error": "Ism va parolni kiriting"}), 400
    hashed = hashlib.sha256(password.encode()).hexdigest()
    if username == "admin" and hashed == ADMIN_HASH:
        token = create_jwt("admin", "admin")
        return jsonify({
            "success": True,
            "token": token,
            "role": "admin",
            "redirect": "multiverse.html"
        })
    if not supabase:
        return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        result = supabase.table("users").select("id, username, password_hash, role").eq("username", username).execute()
        if not result.data:
            return jsonify({"error": "Ism yoki parol noto'g'ri"}), 401
        user = result.data[0]
        if user.get("password_hash") != hashed:
            return jsonify({"error": "Ism yoki parol noto'g'ri"}), 401
        token = create_jwt(user["id"], user.get("role", "human"))
        return jsonify({
            "success": True,
            "token": token,
            "role": user.get("role", "human"),
            "redirect": "multiverse.html"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        @app.route('/api/me', methods=['GET'])
def me():
    auth_present = "Authorization" in request.headers
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_present:
        if not auth_header:
            return jsonify({"error": "Invalid authorization header"}), 401
        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid authorization header"}), 401
        payload = get_jwt_payload()
        if not payload or not payload.get("sub"):
            return jsonify({"error": "Invalid or expired token"}), 401
        user_id = payload["sub"]
        role = payload.get("role", "human")
        if user_id == "admin" and role == "admin":
            return jsonify({"authenticated": True, "id": "admin", "username": "admin", "role": "admin"})
        if not supabase:
            return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
        try:
            result = supabase.table("users").select("id, username, role, email, email_verified").eq("id", int(user_id)).execute()
            if not result.data:
                return jsonify({"error": "Foydalanuvchi topilmadi"}), 404
            u = result.data[0]
            return jsonify({
                "authenticated": True,
                "id": u["id"],
                "username": u["username"],
                "role": u.get("role", "human"),
                "email": u.get("email"),
                "email_verified": u.get("email_verified", False)
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    session_user = session.get("user_id")
    if not session_user:
        return jsonify({"error": "Authentication required"}), 401
    if not supabase:
        return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        result = supabase.table("users").select("id, username, role, email, email_verified").eq("id", int(session_user)).execute()
        if not result.data:
            return jsonify({"error": "Foydalanuvchi topilmadi"}), 404
        u = result.data[0]
        return jsonify({
            "authenticated": True,
            "id": u["id"],
            "username": u["username"],
            "role": u.get("role", "human"),
            "email": u.get("email"),
            "email_verified": u.get("email_verified", False)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    data = request.json or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"valid": False, "error": "Token kerak"}), 400
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer="blip-multiverse")
        return jsonify({
            "valid": True,
            "sub": payload.get("sub"),
            "role": payload.get("role", "human")
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token muddati tugagan"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Token yaroqsiz"}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Chiqdingiz"})


@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    auth_present = "Authorization" in request.headers
    if not auth_present:
        return jsonify({"error": "Authentication required"}), 401
    payload = get_jwt_payload()
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401
    if payload.get("sub") != "admin" or payload.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    if not supabase:
        return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500
    try:
        users = supabase.table("users").select("id", count="exact").execute()
        return jsonify({
            "success": True,
            "total_users": users.count if hasattr(users, "count") else len(users.data or []),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==========================================
# OAuth — GOOGLE
# ==========================================
@app.route('/api/auth/google')
def auth_google():
    redirect_uri = url_for('auth_google_callback', _external=True, _scheme='https')
    return google.authorize_redirect(redirect_uri)


@app.route('/api/auth/google/callback')
def auth_google_callback():
    try:
        token = google.authorize_access_token()
        userinfo = token.get('userinfo') or google.userinfo()
        email = userinfo.get('email')
        provider_id = userinfo.get('sub')
        name = userinfo.get('name') or (email.split('@')[0] if email else f"user_{provider_id}")
        if not provider_id:
            return redirect(f"{FRONTEND_PAGE}/index.html?error=oauth_failed")

        existing = supabase.table("auth_identities").select("user_id").eq("provider", "google").eq("provider_user_id", str(provider_id)).execute()
        if existing.data and len(existing.data) > 0:
            user_id = existing.data[0]["user_id"]
        else:
            username = name.lower().replace(" ", "_")[:20] or f"google_{provider_id[:8]}"
            new_user = supabase.table("users").insert({
                "username": username,
                "email": email,
                "email_verified": True,
                "role": "human"
            }).execute()
            user_id = new_user.data[0]["id"]
            supabase.table("auth_identities").insert({
                "user_id": user_id,
                "provider": "google",
                "provider_user_id": str(provider_id)
            }).execute()

        session.permanent = True
        session["user_id"] = user_id
        session["username"] = name
        session["role"] = "human"
        return redirect(f"{FRONTEND_PAGE}/multiverse.html")
    except Exception as e:
        return redirect(f"{FRONTEND_PAGE}/index.html?error=google_{str(e)[:40]}")


# ==========================================
# OAuth — GITHUB
# ==========================================
@app.route('/api/auth/github')
def auth_github():
    redirect_uri = url_for('auth_github_callback', _external=True, _scheme='https')
    return github.authorize_redirect(redirect_uri)


@app.route('/api/auth/github/callback')
def auth_github_callback():
    try:
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        profile = resp.json()
        provider_id = str(profile.get("id"))
        login_name = profile.get("login") or f"github_{provider_id[:8]}"
        email = profile.get("email")

        existing = supabase.table("auth_identities").select("user_id").eq("provider", "github").eq("provider_user_id", provider_id).execute()
        if existing.data and len(existing.data) > 0:
            user_id = existing.data[0]["user_id"]
        else:
            new_user = supabase.table("users").insert({
                "username": login_name.lower()[:20],
                "email": email,
                "email_verified": bool(email),
                "role": "human"
            }).execute()
            user_id = new_user.data[0]["id"]
            supabase.table("auth_identities").insert({
                "user_id": user_id,
                "provider": "github",
                "provider_user_id": provider_id
            }).execute()

        session.permanent = True
        session["user_id"] = user_id
        session["username"] = login_name
        session["role"] = "human"
        return redirect(f"{FRONTEND_PAGE}/multiverse.html")
    except Exception as e:
        return redirect(f"{FRONTEND_PAGE}/index.html?error=github_{str(e)[:40]}")


# ==========================================
# AI — Turing
# ==========================================
@app.route('/api/chat', methods=['POST'])
def chat():
    user, err = check_auth()
    if err:
        return err
    data = request.json or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Xabar bo'sh"}), 400
    if not GEMINI_API_KEY:
        return jsonify({"error": "AI sozlanmagan"}), 500
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": message}]}]}
        r = make_request_with_retry(url, {"Content-Type": "application/json"}, payload)
        if r.status_code == 200:
            reply = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify({"success": True, "reply": reply})
        return jsonify({"error": f"AI xato: {r.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==========================================
# QIDIRUV
# ==========================================
@app.route('/api/search', methods=['POST'])
def search():
    user, err = check_auth()
    if err:
        return err
    data = request.json or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "So'rov bo'sh"}), 400
    try:
        results = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=5):
                results.append({"title": r.get("title"), "url": r.get("href"), "snippet": r.get("body")})
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==========================================
# EMAIL OTP blueprint
# ==========================================
if init_email_auth is not None and supabase is not None:
    init_email_auth(app, supabase, create_jwt)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
