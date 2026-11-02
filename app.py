from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import uuid
import requests
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, unquote

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

ADMIN_HASH = os.environ.get("ADMIN_HASH", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

users_db = {}
tokens_db = {}

# ==========================================
# ASOSIY VA LOGIN QISMLARI
# ==========================================
@app.route('/')
def home():
    return "Blip Flask Backend ishlayapti! 🚀"

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').lower()
    password = data.get('password', '')
    if not username or not password: return jsonify({"error": "Ism va parol kerak"}), 400
    if len(username) < 3: return jsonify({"error": "Ism kamida 3 harf"}), 400
    if username in users_db: return jsonify({"error": "Bu ism band!"}), 400
    hashed = hashlib.sha256(password.encode()).hexdigest()
    users_db[username] = {"password": hashed, "role": "human"}
    return jsonify({"success": True, "message": "Ro'yxatdan o'tdingiz!"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').lower()
    password = data.get('password', '')
    if not username or not password: return jsonify({"error": "Ism va parolni kiriting"}), 400
    hashed = hashlib.sha256(password.encode()).hexdigest()
    
    if username == "admin" and hashed == ADMIN_HASH:
        token = str(uuid.uuid4())
        tokens_db[token] = {"role": "admin", "name": "Admin"}
        return jsonify({"success": True, "token": token, "role": "admin", "redirect": "multiverse.html"})
        
    user = users_db.get(username)
    if user and user["password"] == hashed:
        token = str(uuid.uuid4())
        tokens_db[token] = {"role": "human", "name": username}
        return jsonify({"success": True, "token": token, "role": "human", "redirect": "multiverse.html"})
    return jsonify({"error": "Ism yoki parol xato!"}), 401

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
    if token in tokens_db and tokens_db[token]["role"] == "admin":
        return jsonify({
            "success": True,
            "total_users": len(users_db),
            "online_users": len(tokens_db),
            "users": list(users_db.keys())
        })
    return jsonify({"error": "Ruxsat yo'q!"}), 403

# ==========================================
# AI CHAT VA IMTOHON
# ==========================================
@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message')
    sys_prompt = data.get('systemPrompt', 'Sen foydali AI yordamchisan.')

    if OPENROUTER_API_KEY:
        try:
            response = requests.post(
                url="https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"},
                json={"model": "google/gemini-2.0-flash-exp:free", "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": message}]},
                timeout=30
            )
            if response.status_code == 200:
                reply = response.json()['choices'][0]['message']['content']
                return jsonify({"success": True, "reply": reply, "provider": "OpenRouter"})
        except Exception as e:
            print(f"OpenRouter xatosi: {e}")

    if GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
            payload = {"contents": [{"role": "user", "parts": [{"text": message}]}], "systemInstruction": {"parts": [{"text": sys_prompt}]}}
            res = requests.post(url, json=payload)
            reply = res.json()['candidates'][0]['content']['parts'][0]['text']
            return jsonify({"success": True, "reply": reply, "provider": "Gemini"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Hech qanday AI kaliti topilmadi"}), 500

@app.route('/api/ai-login', methods=['POST'])
def ai_login():
    data = request.json
    answers = data.get('answers', [])
    if len(answers) < 30: return jsonify({"error": "30 ta savolga javob bering"}), 400
    prompt = f"Sen imtihon tekshiruvchisisan. AI 30 ta savolga javob berdi: {answers}. Agar mantiqan to'g'ri va AI darajasida bo'lsa 'PASS', aks holda 'FAIL' deb yoz."
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    try:
        res = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]})
        result = res.json()['candidates'][0]['content']['parts'][0]['text'].strip().upper()
        if "PASS" in result:
            token = str(uuid.uuid4())
            tokens_db[token] = {"role": "ai", "name": "AI_Node"}
            return jsonify({"success": True, "token": token, "redirect": "ai_multiverse.html"})
        return jsonify({"error": "Javoblar yetarli emas."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# YANGI QIDIRUV TIZIMI (DUCKDUCKGO)
# ==========================================
class DDGParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results = []
        self.current = None
        self.capture = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "").split()

        if tag == "a" and "result__a" in classes:
            self.current = {"title": "", "url": attrs.get("href", ""), "snippet": ""}
            self.capture = "title"
        elif self.current and "result__snippet" in classes:
            self.capture = "snippet"

    def handle_data(self, data):
        if self.current and self.capture:
            self.current[self.capture] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.current and self.capture == "title":
            self.capture = None
        if tag in ("a", "div") and self.current:
            if self.current["title"].strip() and self.current["url"]:
                if len(self.results) < 10:
                    self.results.append(self.current)
                self.current = None
                self.capture = None

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get("q", "").strip()
    if len(query) < 2:
        return jsonify({"success": False, "error": "Kamida 2 ta belgi kiriting."}), 400
    if len(query) > 200:
        return jsonify({"success": False, "error": "Qidiruv matni juda uzun."}), 400

    try:
        response = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15
        )
        response.raise_for_status()

        parser = DDGParser()
        parser.feed(response.text)
        results = []

        for item in parser.results:
            url = item["url"]
            if url.startswith("//"): url = "https:" + url
            if "duckduckgo.com/l/" in url:
                target = parse_qs(urlparse(url).query).get("uddg")
                if target: url = unquote(target[0])
            if not url.startswith(("http://", "https://")): continue
            results.append({"title": item["title"].strip(), "url": url, "snippet": item["snippet"].strip()})

        return jsonify({"success": True, "query": query, "results": results})
    except Exception:
        return jsonify({"success": False, "error": "Qidiruv xizmati vaqtincha ishlamayapti."}), 502

# ==========================================
# SERVERNI ISHGA TUSHIRISH
# ==========================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
