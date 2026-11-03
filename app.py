from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import uuid
import requests
import time
from ddgs import DDGS
from supabase import create_client, Client

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

ADMIN_HASH = os.environ.get("ADMIN_HASH", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

tokens_db = {}

@app.route('/')
def home():
    status = "Supabase ulangan ✅" if supabase else "Supabase ULANMAGAN ❌"
    return f"Blip Flask Backend ishlayapti! 🚀 ({status})"

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

@app.route('/api/register', methods=['POST'])
def register():
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

    if username == "admin" and hashed == ADMIN_HASH:
        token = str(uuid.uuid4())
        tokens_db[token] = {"role": "admin", "name": "Admin"}
        return jsonify({"success": True, "token": token, "role": "admin", "redirect": "multiverse.html"})

    if not supabase: return jsonify({"error": "Ma'lumotlar bazasi ulanmagan"}), 500

    try:
        result = supabase.table("users").select("*").eq("username", username).execute()
        if result.data and len(result.data) > 0:
            user = result.data[0]
            if user["password_hash"] == hashed:
                token = str(uuid.uuid4())
                tokens_db[token] = {"role": "human", "name": username}
                return jsonify({"success": True, "token": token, "role": "human", "redirect": "multiverse.html"})
        return jsonify({"error": "Ism yoki parol xato!"}), 401
    except Exception as e:
        return jsonify({"error": f"Baza xatosi: {str(e)}"}), 500

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    data = request.json
    token = data.get('token')
    if token in tokens_db: return jsonify({"valid": True, "role": tokens_db[token]["role"]})
    return jsonify({"valid": False}), 401

@app.route('/api/admin/stats', methods=['POST'])
def admin_stats():
    data = request.json
    token = data.get('token')
    if token not in tokens_db or tokens_db[token]["role"] != "admin":
        return jsonify({"error": "Ruxsat yo'q!"}), 403
    if not supabase: return jsonify({"error": "Baza ulanmagan"}), 500

    try:
        result = supabase.table("users").select("username").execute()
        users_list = [u["username"] for u in result.data] if result.data else []
        return jsonify({"success": True, "total_users": len(users_list), "online_users": len(tokens_db), "users": users_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message')
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
    data = request.json
    answers = data.get('answers', [])
    if len(answers) < 30: return jsonify({"error": "30 ta savolga javob bering"}), 400
    prompt = f"Sen imtihon tekshiruvchisisan. AI 30 ta savolga javob berdi: {answers}. Agar mantiqan to'g'ri bo'lsa 'PASS', aks holda 'FAIL' deb yoz."
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    try:
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        response = make_request_with_retry(url, {}, payload)
        result = response.json()['candidates'][0]['content']['parts'][0]['text'].strip().upper()
        if "PASS" in result:
            token = str(uuid.uuid4())
            tokens_db[token] = {"role": "ai", "name": "AI_Node"}
            return jsonify({"success": True, "token": token, "redirect": "ai_multiverse.html"})
        return jsonify({"error": "Javoblar yetarli emas."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search():
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
