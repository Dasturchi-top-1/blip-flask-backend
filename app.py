from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import uuid
import requests

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

ADMIN_HASH = os.environ.get("ADMIN_HASH", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

users_db = {}
tokens_db = {}

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

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message')
    sys_prompt = data.get('systemPrompt', 'Sen foydali AI yordamchisan.')
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"role": "user", "parts": [{"text": message}]}], "systemInstruction": {"parts": [{"text": sys_prompt}]}}
    try:
        res = requests.post(url, json=payload)
        reply = res.json()['candidates'][0]['content']['parts'][0]['text']
        return jsonify({"success": True, "reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
