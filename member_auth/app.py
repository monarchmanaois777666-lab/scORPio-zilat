from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import string
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = Path(os.getenv("APP_DOCS_DIR", ROOT / "docs")).resolve()
LOGIN_PAGE = Path(__file__).with_name("login.html")
LANDING_PAGE = Path(__file__).with_name("landing.html")
DB_PATH = Path(os.getenv("MEMBER_DB_PATH", ROOT / "member_auth.sqlite3"))
OWNER_EMAIL = os.getenv("MEMBER_OWNER_EMAIL", "").strip()
COOKIE_NAME = "scorpio_member_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1").lower() not in {"0", "false", "no"}
SESSION_SECONDS = 30 * 24 * 60 * 60
APP_ACCESS_SECONDS = 30 * 24 * 60 * 60
CODE_SECONDS = 24 * 60 * 60
PBKDF2_ITERATIONS = 600_000


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


@contextmanager
def connect() -> Any:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS members (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                access_expires_at INTEGER,
                code_hash TEXT,
                code_expires_at INTEGER,
                code_purpose TEXT,
                code_sent_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                window_started_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL
            );
            """
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="scORPio zilat member access", docs_url=None, redoc_url=None, lifespan=lifespan)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", normalized):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    return normalized


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_access_code(code: str) -> str:
    return hash_token(re.sub(r"[^A-Z0-9]", "", code.upper()))


def new_access_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


def send_owner_code(email: str, code: str, purpose: str) -> None:
    host = os.getenv("MEMBER_SMTP_HOST", "").strip()
    username = os.getenv("MEMBER_SMTP_USERNAME", "").strip()
    password = os.getenv("MEMBER_SMTP_PASSWORD", "")
    sender = os.getenv("MEMBER_SMTP_FROM", username).strip()
    if not (OWNER_EMAIL and host and username and password and sender):
        raise RuntimeError("Owner email delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = f"scORPio zilat: {purpose} code requested"
    message["From"] = sender
    message["To"] = OWNER_EMAIL
    message.set_content(
        f"A member requested {purpose.lower()} for {email}.\n\n"
        f"Give this one-time code only to that member:\n\n{code}\n\n"
        "The code expires in 24 hours. It is single-use."
    )

    port = int(os.getenv("MEMBER_SMTP_PORT", "587"))
    timeout = 15
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as smtp:
            smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(message)


def rate_allowed(key: str, limit: int, window_seconds: int) -> bool:
    current = now_ts()
    with connect() as db:
        row = db.execute("SELECT window_started_at, attempts FROM rate_limits WHERE key = ?", (key,)).fetchone()
        if row is None or current - row["window_started_at"] >= window_seconds:
            db.execute(
                "INSERT INTO rate_limits(key, window_started_at, attempts) VALUES (?, ?, 1) "
                "ON CONFLICT(key) DO UPDATE SET window_started_at = excluded.window_started_at, attempts = 1",
                (key, current),
            )
            return True
        if row["attempts"] >= limit:
            return False
        db.execute("UPDATE rate_limits SET attempts = attempts + 1 WHERE key = ?", (key,))
        return True


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_member(request: Request) -> sqlite3.Row | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    current = now_ts()
    with connect() as db:
        row = db.execute(
            "SELECT m.*, s.expires_at AS session_expires_at FROM sessions s "
            "JOIN members m ON m.id = s.member_id WHERE s.token_hash = ?",
            (hash_token(token),),
        ).fetchone()
        if row is None:
            return None
        if row["session_expires_at"] <= current:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
            return None
        return row


def is_active(member: sqlite3.Row | None) -> bool:
    return bool(member and member["access_expires_at"] and member["access_expires_at"] > now_ts())


def add_session(response: Response, member_id: str) -> None:
    token = secrets.token_urlsafe(32)
    with connect() as db:
        db.execute(
            "INSERT INTO sessions(token_hash, member_id, expires_at) VALUES (?, ?, ?)",
            (hash_token(token), member_id, now_ts() + SESSION_SECONDS),
        )
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def clear_session(response: Response, request: Request) -> None:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        with connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")


def no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def set_code(member_id: str, email: str, purpose: str) -> None:
    code = new_access_code()
    try:
        send_owner_code(email, code, purpose)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="The owner could not be notified. Try again later.") from exc
    with connect() as db:
        db.execute(
            "UPDATE members SET code_hash = ?, code_expires_at = ?, code_purpose = ?, code_sent_at = ? WHERE id = ?",
            (hash_access_code(code), now_ts() + CODE_SECONDS, purpose, now_ts(), member_id),
        )


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)


class AccessCode(BaseModel):
    code: str = Field(min_length=8, max_length=64)


@app.get("/api/auth/status")
def auth_status(request: Request, response: Response) -> Any:
    member = current_member(request)
    no_store(response)
    if not member:
        return {"authenticated": False, "active": False}
    expires = member["access_expires_at"]
    return {
        "authenticated": True,
        "active": is_active(member),
        "email": member["email"],
        "expiresAt": datetime.fromtimestamp(expires, timezone.utc).isoformat() if expires else None,
        "codePending": bool(member["code_hash"] and member["code_expires_at"] > now_ts()),
    }


@app.post("/api/auth/register")
def register(payload: Credentials, request: Request, response: Response) -> Any:
    email = normalize_email(payload.email)
    if not rate_allowed("register:" + client_key(request), 5, 3600):
        raise HTTPException(status_code=429, detail="Too many sign-up attempts. Try again later.")
    if not rate_allowed("register-email:" + hash_token(email), 3, 86400):
        raise HTTPException(status_code=429, detail="Too many sign-up attempts. Try again tomorrow.")

    with connect() as db:
        exists = db.execute("SELECT 1 FROM members WHERE email = ?", (email,)).fetchone()
    if exists:
        raise HTTPException(status_code=409, detail="An account with that email already exists. Sign in instead.")

    member_id = secrets.token_hex(16)
    try:
        registration_code = send_code_email_for_registration(email)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="The owner could not be notified. Try again later.") from exc

    with connect() as db:
        try:
            db.execute(
                "INSERT INTO members(id, email, password_hash, code_hash, code_expires_at, code_purpose, code_sent_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'activation', ?, ?)",
                (member_id, email, hash_password(payload.password), hash_access_code(registration_code), now_ts() + CODE_SECONDS, now_ts(), now_ts()),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="An account with that email already exists. Sign in instead.") from exc

    add_session(response, member_id)
    no_store(response)
    return {"authenticated": True, "active": False, "message": "Account created. Ask the owner for your one-time access code."}


def send_code_email_for_registration(email: str) -> str:
    code = new_access_code()
    send_owner_code(email, code, "account activation")
    return code


@app.post("/api/auth/login")
def login(payload: Credentials, request: Request, response: Response) -> Any:
    email = normalize_email(payload.email)
    if not rate_allowed("login:" + client_key(request), 10, 600):
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Wait a few minutes and try again.")
    with connect() as db:
        member = db.execute("SELECT * FROM members WHERE email = ?", (email,)).fetchone()
    if not member or not verify_password(payload.password, member["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    add_session(response, member["id"])
    no_store(response)
    return {"authenticated": True, "active": is_active(member), "message": "Signed in."}


@app.post("/api/auth/redeem")
def redeem(payload: AccessCode, request: Request, response: Response) -> Any:
    member = current_member(request)
    if not member:
        raise HTTPException(status_code=401, detail="Sign in before entering your access code.")
    if not rate_allowed("redeem:" + member["id"], 10, 600):
        raise HTTPException(status_code=429, detail="Too many code attempts. Wait a few minutes and try again.")

    code_hash = hash_access_code(payload.code)
    if not member["code_hash"] or not hmac.compare_digest(code_hash, member["code_hash"]):
        raise HTTPException(status_code=400, detail="That code is not valid for this account.")
    current = now_ts()
    if member["code_expires_at"] <= current:
        raise HTTPException(status_code=400, detail="That code has expired. Request a new one from the owner.")

    expires_at = current + APP_ACCESS_SECONDS
    with connect() as db:
        result = db.execute(
            "UPDATE members SET access_expires_at = ?, code_hash = NULL, code_expires_at = NULL, code_purpose = NULL "
            "WHERE id = ? AND code_hash = ? AND code_expires_at > ?",
            (expires_at, member["id"], member["code_hash"], current),
        )
        if result.rowcount != 1:
            raise HTTPException(status_code=400, detail="That code has already been used or has expired.")
    no_store(response)
    return {"active": True, "expiresAt": datetime.fromtimestamp(expires_at, timezone.utc).isoformat()}


@app.post("/api/auth/request-renewal")
def request_renewal(request: Request, response: Response) -> Any:
    member = current_member(request)
    if not member:
        raise HTTPException(status_code=401, detail="Sign in before requesting renewal.")
    if is_active(member):
        raise HTTPException(status_code=409, detail="Your app access has not expired yet.")
    if member["code_hash"] and member["code_expires_at"] > now_ts():
        return no_store(JSONResponse({"message": "A code is already pending. Contact the owner."}))
    if now_ts() - member["code_sent_at"] < 600:
        raise HTTPException(status_code=429, detail="Wait a few minutes before requesting another code.")

    set_code(member["id"], member["email"], "monthly access renewal")
    no_store(response)
    return {"message": "A new one-time code was sent to the owner. Contact the owner to receive it."}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> Any:
    clear_session(response, request)
    no_store(response)
    return {"authenticated": False}


@app.get("/sw.js", response_class=PlainTextResponse)
def disable_old_service_worker(response: Response) -> Any:
    script = "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil((async()=>{for(const k of await caches.keys())await caches.delete(k);await self.registration.unregister()})()));"
    no_store(response)
    response.headers["Service-Worker-Allowed"] = "/"
    return PlainTextResponse(script, headers={"Cache-Control": "no-store"})


def serve_private_file(path: str, request: Request) -> Response:
    member = current_member(request)
    if not is_active(member):
        return no_store(FileResponse(LOGIN_PAGE))
    target = (DOCS_DIR / path).resolve()
    if target != DOCS_DIR and DOCS_DIR not in target.parents:
        raise HTTPException(status_code=404)
    if target.is_dir():
        target = target / "index.html"
    if not target.is_file():
        raise HTTPException(status_code=404)
    return no_store(FileResponse(target))


@app.get("/", response_class=HTMLResponse)
def home() -> Response:
    return no_store(FileResponse(LANDING_PAGE))


@app.get("/account", response_class=HTMLResponse)
def account() -> Response:
    return no_store(FileResponse(LOGIN_PAGE))


@app.get("/app", response_class=HTMLResponse)
@app.get("/app/", response_class=HTMLResponse)
def member_app(request: Request) -> Response:
    return serve_private_file("index.html", request)


@app.get("/{asset_path:path}")
def private_assets(asset_path: str, request: Request) -> Response:
    if asset_path.startswith("api/"):
        raise HTTPException(status_code=404)
    if asset_path == "index.html":
        return RedirectResponse("/app", status_code=307)
    if asset_path == "robots.txt":
        return PlainTextResponse("User-agent: *\nAllow: /\nDisallow: /app\nDisallow: /account\n")
    if asset_path == "sitemap.xml":
        base_url = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
        if not base_url:
            raise HTTPException(status_code=404)
        return Response(
            content=(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>{base_url}/</loc></url></urlset>"
            ),
            media_type="application/xml",
        )
    return serve_private_file(asset_path, request)