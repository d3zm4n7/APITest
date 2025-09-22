from doctest import Example
from flask import Flask, request, jsonify
import uuid, time

app = Flask(__name__)

@app.get('/health')
def health():
    return{"status": "ok"}

USERS = {"alice@example.com":{"password":"pass123", "role":"user"},
         "admin@example.com":{"password":"admin123", "role":"admin"}}

TOKENS = {}


# bearer token
# def requirer_bearer(req):
#     auth = req.headers.get('Authorization')
#     if not auth.startswith('Bearer '):
#         return None
    
#     return TOKENS.get(token)
# bearer token
def requirer_bearer(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(' ',1)[1].strip()
    return TOKENS.get(token)

@app.post('/login')
def login():
    data = request.get_json()
    print(data)
    email = data.get('email')
    password = data.get('password')
    user = USERS.get(email)
    if not user or user['password'] != password:
        return {"error": "Credentials are bad"},401
    tok = str(uuid.uuid4())
    TOKENS[tok] = {"email":email, 'role':user['role']}
    time.sleep(0.15)

    return {"token": tok,'role': user['role']}


@app.get('/me')
def me():
    principals = requirer_bearer(request)
    if not principals:
        return {"error": "Unauthorized"}, 401
    return {"email": principals['email'], 'role': principals['role']}

@app.get('/admin')
def admin_only():
    user = requirer_bearer(request)
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if user.get('role') != 'admin':
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"ok": True, "secret": "flag-123"}), 200

@app.post('/logout')
def logout():
    # Извлекаем токен из заголовка
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "unauthorized"}), 401
    token = auth.split(' ')[1].strip()

    # Если такого токена нет — считаем, что он недействителен
    if token not in TOKENS:
        return jsonify({"error": "unauthorized"}), 401

    # Удаляем токен, чтобы он перестал работать
    del TOKENS[token]
    return jsonify({"ok": True}), 200

if __name__=="__main__":
    app.run(host='127.0.0.1', port=5000)