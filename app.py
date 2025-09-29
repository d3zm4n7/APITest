from doctest import Example
from flask import Flask, request
import uuid, time

app = Flask(__name__)

@app.get('/health')
def health():
    return{"status": "ok"}

USERS = {"alice@example.com":{"password":"pass123", "role":"user"},
         "admin@example.com":{"password":"admin123", "role":"admin"}}

TOKENS = {}

def require_bearer(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    return TOKENS.get(token)

@app.post("/login")
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

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return {"error": "bad_email"}, 400
    if not password or len(password) < 6:
        return {"error": "bad_password"}, 400
    if email in USERS:
        return {"error": "conflict"}, 409

    USERS[email] = {"password": password, "role": "user"}
    tok = str(uuid.uuid4())
    TOKENS[tok] = {"email": email, "role": "user"}
    return {"token": tok, "email": email, "role": "user"}, 201

@app.post("/change-password")
def change_password():
    principals = require_bearer(request)
    if not principals:
        return {"error": "unauthorized"}, 401

    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""
    email = principals["email"]

    # Validate payload + current password
    user = USERS.get(email)
    if not user or not old_password or not new_password:
        return {"error": "bad_request"}, 400
    if user["password"] != old_password:
        return {"error": "bad_request"}, 400
    if len(new_password) < 6 or new_password == old_password:
        return {"error": "bad_request"}, 400

    # Update password + rotate token
    old_tok = get_bearer_token(request)
    if old_tok:
        TOKENS.pop(old_tok, None)
    USERS[email]["password"] = new_password
    new_tok = str(uuid.uuid4())
    TOKENS[new_tok] = {"email": email, "role": user["role"]}
    return {"token": new_tok}, 200



@app.post("/logout")
def logout():
    principals = require_bearer(request)
    if not principals:
        return {"error": "unauthorized"}, 401

    auth = request.headers.get("Authorization", "")
    token = auth.split(" ", 1)[1].strip()
    TOKENS.pop(token, None)

    return {"ok": True}

@app.get("/me")
def me():
    principalsme = require_bearer(request)
    if not principalsme:
        return {"error": "unauthorized"}, 401
    return {"email": principalsme["email"], "role": principalsme["role"]}

@app.get("/admin")
def admin():
    principalsadmin = require_bearer(request)
    if principalsadmin and principalsadmin.get("role") == "admin":
        print({"OK": True, "secret": "flag-123"})
        return {"OK": True, "secret": "flag-123"}
    elif principalsadmin and principalsadmin.get("role") != "admin":
        return {"error": "forbidden"}, 403
    return  {"error": "unauthorized"}, 401

def get_bearer_token(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth.split(" ", 1)[1].strip()

if __name__=="__main__":
    app.run(host='127.0.0.1', port=5000, use_reloader=False)