
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import sqlite3
import hashlib
import secrets
import hmac
import html
import json
import os

DB_PATH = Path(__file__).resolve().parent / "students.db"
SECRET = os.environ.get(
    "STUDENTCHAT_SECRET",
    "development-only-change-this-secret"
)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS students (
                student_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET,
    same_site="lax",
    https_only=os.environ.get("COOKIE_HTTPS_ONLY") == "1"
)

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + value

def check_password(password, saved):
    salt, expected = saved.split("$", 1)
    actual = hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(actual, expected)

def get_student(student_id):
    with db() as con:
        return con.execute(
            "SELECT student_id, name FROM students WHERE student_id=?",
            (student_id,)
        ).fetchone()

def page(title, content):
    return HTMLResponse(f"""<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:Arial;margin:0;background:#e9edef;color:#222}}
input,button{{font:inherit;padding:12px;border-radius:7px}}
input{{border:1px solid #ccc;width:100%;margin:6px 0}}
button{{border:0;background:#128c55;color:white;cursor:pointer}}
a{{color:#128c55}}
.auth{{max-width:380px;margin:70px auto;background:white;padding:28px;
border-radius:12px}}
.auth button{{width:100%;margin-top:10px}}
#app{{display:flex;max-width:1100px;height:92vh;margin:4vh auto;
background:white;box-shadow:0 3px 18px #0002}}
#sidebar{{width:300px;max-width:40%;border-right:1px solid #ddd;
display:flex;flex-direction:column}}
#brand{{background:#128c55;color:white;padding:18px;font-size:22px}}
#contacts{{overflow-y:auto}}
.contact{{padding:15px;border-bottom:1px solid #eee;cursor:pointer;
overflow-wrap:anywhere}}
.contact:hover,.contact.active{{background:#e4f3eb}}
#chat{{flex:1;min-width:0;display:flex;flex-direction:column}}
#chathead{{padding:17px;background:#f0f2f5;border-bottom:1px solid #ddd}}
#messages{{flex:1;overflow-y:auto;padding:16px;
background:#efeae2;display:flex;flex-direction:column;gap:9px}}
.bubble{{max-width:78%;padding:10px 13px;border-radius:10px;
background:white;overflow-wrap:anywhere;align-self:flex-start}}
.mine{{background:#d9fdd3;align-self:flex-end}}
.time{{display:block;font-size:10px;color:#666;margin-top:5px}}
#sendbar{{display:flex;gap:8px;padding:12px;background:#f0f2f5}}
#sendbar input{{margin:0;flex:1;min-width:0}}
#sendbar button{{min-width:72px}}
.muted{{color:#666;font-size:13px;padding:12px}}
@media(max-width:600px){{
#app{{height:100vh;margin:0}}
#sidebar{{width:36%;max-width:36%}}
#brand{{font-size:17px;padding:12px}}
.contact{{padding:10px;font-size:13px}}
#chathead{{padding:12px}}
#messages{{padding:9px}}
#sendbar{{padding:8px;gap:5px}}
#sendbar input{{padding:9px}}
#sendbar button{{min-width:55px;padding:9px}}
}}
</style></head><body>{content}</body></html>""")

def auth_page(register=False, message=""):
    if register:
        fields = """
        <input name="name" placeholder="Full name" maxlength="80" required>
        <input name="student_id" placeholder="Student ID" maxlength="40" required>
        <input name="password" type="password" placeholder="Password (8+ characters)" minlength="8" maxlength="128" required>
        <input name="confirm_password" type="password" placeholder="Confirm password" minlength="8" maxlength="128" required>
        """
        action = "/register"
        heading = "Create your account"
        button = "Register"
        link = '<a href="/login">Already registered? Login</a>'
    else:
        fields = """
        <input name="student_id" placeholder="Student ID" required>
        <input name="password" type="password" placeholder="Password" required>
        """
        action = "/login"
        heading = "Welcome back"
        button = "Login"
        link = '<a href="/register">New student? Register here</a>'

    notice = f'<p>{html.escape(message)}</p>' if message else ""
    return page("StudentChat", f"""
    <div class="auth">
    <h1 style="color:#128c55;text-align:center">StudentChat</h1>
    <h3>{heading}</h3>{notice}
    <form method="post" action="{action}">
    {fields}<button>{button}</button>
    </form><p>{link}</p></div>
    """)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    sid = request.session.get("student_id")
    student = get_student(sid) if sid else None
    if not student:
        return RedirectResponse("/login", status_code=303)

    return page("StudentChat", """
    <div id="app">
      <aside id="sidebar">
        <div id="brand">StudentChat
          <div style="font-size:12px;margin-top:8px">College messaging</div>
        </div>
        <div class="muted">REGISTERED STUDENTS</div>
        <div id="contacts"></div>
        <form method="post" action="/logout" style="padding:10px">
          <button style="width:100%">Logout</button>
        </form>
      </aside>
      <main id="chat">
        <div id="chathead">Select a student to start chatting</div>
        <div id="messages">
          <p>Select a student from the list.</p>
        </div>
        <form id="sendbar">
          <input id="text" placeholder="Type a message..."
                 maxlength="2000" autocomplete="off" disabled>
          <button id="send" disabled>Send</button>
        </form>
      </main>
    </div>
    <script>
    const contacts = document.getElementById("contacts");
    const messages = document.getElementById("messages");
    const head = document.getElementById("chathead");
    const input = document.getElementById("text");
    const send = document.getElementById("send");
    let selected = null;
    let socket = null;
    let generation = 0;

    function addMessage(m) {
      const bubble = document.createElement("div");
      bubble.className = "bubble" + (m.mine ? " mine" : "");
      const body = document.createElement("div");
      body.textContent = m.message;
      const time = document.createElement("small");
      time.className = "time";
      time.textContent = m.sender + " · " + (m.created_at || "now");
      bubble.append(body, time);
      messages.appendChild(bubble);
      messages.scrollTop = messages.scrollHeight;
    }

    async function loadContacts() {
      const response = await fetch("/api/students");
      if (!response.ok) return;
      const list = await response.json();
      contacts.replaceChildren();
      if (!list.length) {
        contacts.textContent = "No other registered students yet.";
      }
      list.forEach(s => {
        const item = document.createElement("div");
        item.className = "contact";
        item.textContent = s.name + " (" + s.student_id + ")";
        item.onclick = () => openChat(s, item);
        contacts.appendChild(item);
      });
    }

    async function openChat(student, item) {
      selected = student;
      const myGeneration = ++generation;
      document.querySelectorAll(".contact").forEach(
        el => el.classList.remove("active")
      );
      item.classList.add("active");
      head.textContent = student.name + " (" + student.student_id + ")";
      messages.replaceChildren();
      input.disabled = false;
      send.disabled = false;
      if (socket) socket.close();
      socket = null;

      try {
        const response = await fetch(
          "/api/messages/" + encodeURIComponent(student.student_id)
        );
        if (!response.ok || myGeneration !== generation) return;
        const history = await response.json();
        history.forEach(addMessage);
      } catch (e) {
        messages.textContent = "Could not load message history.";
      }

      if (myGeneration !== generation) return;
      const protocol = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(
        protocol + "//" + location.host +
        "/ws/" + encodeURIComponent(student.student_id)
      );
      socket = ws;
      ws.onmessage = event => {
        if (myGeneration !== generation) return;
        const m = JSON.parse(event.data);
        addMessage(m);
      };
      ws.onclose = () => {
        if (myGeneration === generation) {
          head.textContent = student.name + " (connection closed)";
        }
      };
      ws.onerror = () => {
        if (myGeneration === generation) {
          head.textContent = student.name + " (connection error)";
        }
      };
    }

    document.getElementById("sendbar").onsubmit = event => {
      event.preventDefault();
      const message = input.value.trim();
      if (!message || !socket || socket.readyState !== WebSocket.OPEN) {
        return;
      }
      socket.send(JSON.stringify({message}));
      input.value = "";
      input.focus();
    };

    loadContacts();
    </script>
    """)

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    return auth_page(True)

@app.post("/register", response_class=HTMLResponse)
async def register(
    name: str = Form(...),
    student_id: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    name, student_id = name.strip(), student_id.strip()
    if not name or not student_id or len(name) > 80 or len(student_id) > 40:
        return HTMLResponse(auth_page(True, "Please enter valid details."), 400)
    if len(password) < 8 or len(password) > 128:
        return HTMLResponse(auth_page(True, "Password must be 8–128 characters."), 400)
    if password != confirm_password:
        return HTMLResponse(auth_page(True, "Passwords do not match."), 400)

    try:
        with db() as con:
            con.execute(
                "INSERT INTO students VALUES (?, ?, ?)",
                (student_id, name, hash_password(password))
            )
    except sqlite3.IntegrityError:
        return HTMLResponse(auth_page(True, "That Student ID is already registered."), 409)

    return HTMLResponse(page("Registered", """
      <div class="auth"><h2>Registration successful!</h2>
      <a href="/login">Login to StudentChat</a></div>
    """))

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return auth_page()

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    student_id: str = Form(...),
    password: str = Form(...)
):
    with db() as con:
        student = con.execute(
            "SELECT * FROM students WHERE student_id=?",
            (student_id.strip(),)
        ).fetchone()

    if not student or not check_password(password, student["password_hash"]):
        return HTMLResponse(auth_page(False, "Invalid Student ID or password."), 401)

    request.session.clear()
    request.session["student_id"] = student["student_id"]
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

@app.get("/api/students")
async def students(request: Request):
    sid = request.session.get("student_id")
    if not sid or not get_student(sid):
        return HTMLResponse("Login required", 401)
    with db() as con:
        rows = con.execute(
            "SELECT student_id, name FROM students WHERE student_id != ? ORDER BY name",
            (sid,)
        ).fetchall()
    return [dict(row) for row in rows]

@app.get("/api/messages/{peer_id}")
async def message_history(peer_id: str, request: Request):
    sid = request.session.get("student_id")
    if not sid or not get_student(sid):
        return HTMLResponse("Login required", 401)
    if not get_student(peer_id):
        return HTMLResponse("Student not found", 404)

    with db() as con:
        rows = con.execute("""
            SELECT id, sender, receiver, message, created_at
            FROM messages
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY id LIMIT 500
        """, (sid, peer_id, peer_id, sid)).fetchall()

    return [
        {
            "id": r["id"],
            "sender": r["sender"],
            "message": r["message"],
            "created_at": r["created_at"],
            "mine": r["sender"] == sid
        }
        for r in rows
    ]

# Active sockets grouped by the two students in a private conversation.
rooms = {}

@app.websocket("/ws/{peer_id}")
async def chat_socket(ws: WebSocket, peer_id: str):
    sid = ws.scope.get("session", {}).get("student_id")
    if not sid or not get_student(sid) or sid == peer_id or not get_student(peer_id):
        await ws.close(code=1008)
        return

    room = tuple(sorted((sid, peer_id)))
    await ws.accept()
    rooms.setdefault(room, set()).add(ws)

    try:
        while True:
            data = await ws.receive_json()
            message = data.get("message", "")
            if not isinstance(message, str):
                continue
            message = message.strip()
            if not message or len(message) > 2000:
                continue

            with db() as con:
                cur = con.execute(
                    "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                    (sid, peer_id, message)
                )
                row = con.execute(
                    "SELECT created_at FROM messages WHERE id=?",
                    (cur.lastrowid,)
                ).fetchone()

            payload = json.dumps({
                "sender": sid,
                "message": message,
                "created_at": row["created_at"],
                "mine": False
            })

            # Each recipient renders the message with their own perspective.
            for connection in list(rooms.get(room, set())):
                try:
                    outgoing = json.loads(payload)
                    outgoing["mine"] = (
                        connection.scope.get("session", {}).get("student_id")
                        == sid
                    )
                    await connection.send_text(json.dumps(outgoing))
                except Exception:
                    rooms.get(room, set()).discard(connection)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        rooms.get(room, set()).discard(ws)
        if room in rooms and not rooms[room]:
            del rooms[room]
