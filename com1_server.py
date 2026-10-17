"""Com1 online messaging server (starter).
Deploy this file on a Python host. Set COM1_SECRET before deployment.
"""
import os, sqlite3, hashlib, hmac, secrets, time
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("COM1_DB_PATH", "com1_server.db")
SECRET = os.environ.get("COM1_SECRET")
app = FastAPI(title="Com1 Server", version="0.1")

class AuthIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)
class MessageIn(BaseModel):
    recipient: str = Field(min_length=3, max_length=32)
    message: str = Field(min_length=1, max_length=4000)

def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    return con

def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()

def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, pw_hash TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL)")
init_db()

@app.get("/")
def health():
    return {"service":"Com1", "status":"online"}

@app.post("/register")
def register(data: AuthIn):
    salt = secrets.token_hex(16)
    try:
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?,?)", (data.username, salt, pw_hash(data.password, salt)))
        return {"ok": True}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")

def issue_token(username):
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (digest, username, int(time.time()) + 30*24*3600))
    return token

@app.post("/login")
def login(data: AuthIn):
    with db() as c:
        user = c.execute("SELECT salt,pw_hash FROM users WHERE username=?", (data.username,)).fetchone()
    if not user or not hmac.compare_digest(pw_hash(data.password, user['salt']), user['pw_hash']):
        raise HTTPException(401, "Invalid username or password")
    return {"token": issue_token(data.username), "username": data.username}

def current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    token = authorization[7:]
    digest = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute("SELECT username,expires FROM sessions WHERE token_hash=?", (digest,)).fetchone()
    if not row or row['expires'] < int(time.time()):
        raise HTTPException(401, "Session expired")
    return row['username']

@app.post("/messages")
def send_message(data: MessageIn, authorization: str | None = Header(default=None)):
    sender = current_user(authorization)
    with db() as c:
        exists = c.execute("SELECT 1 FROM users WHERE username=?", (data.recipient,)).fetchone()
        if not exists:
            raise HTTPException(404, "Recipient not found")
        cur = c.execute("INSERT INTO messages(sender,recipient,body,created) VALUES(?,?,?,?)", (sender,data.recipient,data.message,int(time.time())))
        return {"id":cur.lastrowid, "ok":True}

@app.get("/messages/{with_user}")
def get_messages(with_user: str, authorization: str | None = Header(default=None), after: int = 0):
    me = current_user(authorization)
    with db() as c:
        rows = c.execute("SELECT id,sender,recipient,body,created FROM messages WHERE id>? AND ((sender=? AND recipient=?) OR (sender=? AND recipient=?)) ORDER BY id LIMIT 500", (after,me,with_user,with_user,me)).fetchall()
    return {"messages":[dict(r) for r in rows]}
