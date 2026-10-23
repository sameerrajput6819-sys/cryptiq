"""CRYPTIQ Flask backend.

Privacy rule: this API never receives the passwords users TEST in the analyzer.
The only password it ever sees is the user's own ACCOUNT password (register /
login / delete account), which is stored only as a salted Werkzeug hash.
Request bodies are never logged.
"""
import hmac
import math
import os
import re
import secrets
import unicodedata
from datetime import timedelta
from decimal import Decimal
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mysql.connector import Error as MySQLError
from mysql.connector import IntegrityError, errorcode
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import database

load_dotenv()


def _env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# App + configuration
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="")

_secret = os.environ.get("SECRET_KEY", "")
if len(_secret) < 32:
    raise RuntimeError(
        "SECRET_KEY is missing or too short (need 32+ characters). Generate one with:\n"
        '  python -c "import secrets; print(secrets.token_hex(32))"\n'
        "and put it in your .env file."
    )
database.check_config()

app.config.update(
    SECRET_KEY=_secret,
    SESSION_COOKIE_NAME="cryptiq_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", True),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "12"))),
    MAX_CONTENT_LENGTH=16 * 1024,  # API bodies are tiny; reject anything larger
)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# Limits on stored rows per user, so one account cannot fill the database.
MAX_ANALYSES_PER_USER = 500
MAX_QUIZ_RESULTS_PER_USER = 1000

STRENGTH_CATEGORIES = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")

# Used to spend equal time when a login email does not exist (avoids a timing hint).
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))

# connect-src must allow the Have I Been Pwned range API used by the breach check.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' https://api.pwnedpasswords.com; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def error(message, status=400):
    return jsonify({"error": message}), status


@app.errorhandler(ApiError)
def handle_api_error(e):
    return error(e.message, e.status)


_HTTP_MESSAGES = {
    400: "Bad request.",
    404: "Not found.",
    405: "Method not allowed.",
    413: "Request too large.",
    429: "Too many requests. Please wait a moment and try again.",
    500: "Something went wrong on the server.",
}


@app.errorhandler(HTTPException)
def handle_http_error(e):
    if request.path.startswith("/api/"):
        return error(_HTTP_MESSAGES.get(e.code, e.name), e.code or 500)
    return e


@app.errorhandler(MySQLError)
def handle_db_error(e):
    app.logger.exception("Database error")  # traceback only; request bodies are never logged
    return error("The database is temporarily unavailable. Please try again later.", 503)


# --------------------------------------------------------------------------
# Security headers, CSRF
# --------------------------------------------------------------------------
@app.after_request
def add_headers(resp):
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def csrf_token():
    token = session.get("csrf")
    if not token:
        token = session["csrf"] = secrets.token_urlsafe(32)
    return token


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
        sent = request.headers.get("X-CSRF-Token", "").encode()
        expected = session.get("csrf", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            return error("Security token missing or expired. Please try again.", 403)


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
def json_body(allowed):
    """Return the JSON object body, rejecting anything with unexpected fields."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Request body must be a JSON object.")
    if set(data) - set(allowed):
        raise ApiError("Unexpected fields are not accepted.")
    return data


def clean_username(value):
    if not isinstance(value, str):
        raise ApiError("Username is required.")
    value = " ".join(value.split())
    if not 2 <= len(value) <= 100:
        raise ApiError("Username must be 2 to 100 characters.")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise ApiError("Username contains invalid characters.")
    return value


def clean_email(value):
    if not isinstance(value, str):
        raise ApiError("Email is required.")
    value = value.strip().lower()
    if len(value) > 255 or not EMAIL_RE.match(value):
        raise ApiError("Please enter a valid email address.")
    return value


def clean_new_password(value, email):
    if not isinstance(value, str):
        raise ApiError("Password is required.")
    if not 10 <= len(value) <= 128:
        raise ApiError("Account password must be 10 to 128 characters.")
    if value.lower() == email:
        raise ApiError("Account password must not be the same as your email.")
    return value


def clean_login_password(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ApiError("Invalid email or password.", 401)
    return value


def as_int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(f"{name} must be a whole number.")
    if not low <= value <= high:
        raise ApiError(f"{name} must be between {low} and {high}.")
    return value


def as_entropy(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError("estimated_entropy must be a number.")
    if not math.isfinite(value) or not 0 <= value <= 100000:
        raise ApiError("estimated_entropy must be between 0 and 100000.")
    return Decimal(f"{value:.2f}")


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def current_user():
    if "user" in g:
        return g.user
    g.user = None
    uid = session.get("user_id")
    if isinstance(uid, int):
        with database.get_cursor() as cur:
            cur.execute("SELECT user_id, username, email FROM users WHERE user_id = %s", (uid,))
            g.user = cur.fetchone()
        if g.user is None:
            session.pop("user_id", None)  # account no longer exists
    return g.user


def public_user(user):
    return {"username": user["username"], "email": user["email"]} if user else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            raise ApiError("Please log in to use this feature.", 401)
        return fn(*args, **kwargs)
    return wrapper


def start_session(user_id):
    session.clear()  # new session on login prevents session fixation
    session["user_id"] = user_id
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# --------------------------------------------------------------------------
# Auth API
# --------------------------------------------------------------------------
@app.get("/api/session")
def get_session():
    user = current_user()
    return jsonify(authenticated=user is not None, user=public_user(user), csrf_token=csrf_token())


@app.post("/api/register")
@limiter.limit("5 per minute; 30 per hour")
def register():
    data = json_body(("username", "email", "password"))
    username = clean_username(data.get("username"))
    email = clean_email(data.get("email"))
    password = clean_new_password(data.get("password"), email)
    pw_hash = generate_password_hash(password)  # salted scrypt (Werkzeug default)
    try:
        with database.get_cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                (username, email, pw_hash),
            )
            user_id = cur.lastrowid
    except IntegrityError as e:
        if e.errno == errorcode.ER_DUP_ENTRY:
            raise ApiError("An account with this email already exists.", 409)
        raise
    start_session(user_id)
    return jsonify(user={"username": username, "email": email}, csrf_token=session["csrf"]), 201


@app.post("/api/login")
@limiter.limit("10 per minute; 100 per hour")
def login():
    data = json_body(("email", "password"))
    email = data.get("email")
    password = clean_login_password(data.get("password"))
    if not isinstance(email, str) or len(email) > 255:
        raise ApiError("Invalid email or password.", 401)
    email = email.strip().lower()
    with database.get_cursor() as cur:
        cur.execute(
            "SELECT user_id, username, email, password_hash FROM users WHERE email = %s", (email,)
        )
        row = cur.fetchone()
    valid = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
    if row is None or not valid:
        raise ApiError("Invalid email or password.", 401)
    start_session(row["user_id"])
    return jsonify(user={"username": row["username"], "email": row["email"]}, csrf_token=session["csrf"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True, csrf_token=csrf_token())


@app.delete("/api/account")
@limiter.limit("3 per hour")
@login_required
def delete_account():
    """Deliberate account deletion: removes the user's records, then the user, in one transaction."""
    data = json_body(("password",))
    password = data.get("password")
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        raise ApiError("Password is required to delete your account.")
    uid = current_user()["user_id"]
    with database.get_cursor() as cur:
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (uid,))
        row = cur.fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        raise ApiError("Incorrect password.", 403)
    with database.get_cursor(commit=True) as cur:
        cur.execute("DELETE FROM analysis_history WHERE user_id = %s", (uid,))
        cur.execute("DELETE FROM quiz_results WHERE user_id = %s", (uid,))
        cur.execute("DELETE FROM users WHERE user_id = %s", (uid,))
    session.clear()
    return jsonify(ok=True, csrf_token=csrf_token())


# --------------------------------------------------------------------------
# Public content API (no account needed)
# --------------------------------------------------------------------------
@app.get("/api/scenarios")
def get_scenarios():
    with database.get_cursor() as cur:
        cur.execute(
            "SELECT scenario_id, scenario_name, guesses_per_second, description "
            "FROM attack_scenarios ORDER BY guesses_per_second ASC, scenario_id ASC"
        )
        rows = cur.fetchall()
    resp = jsonify(
        scenarios=[
            {
                "scenario_id": r["scenario_id"],
                "scenario_name": r["scenario_name"],
                "guesses_per_second": int(r["guesses_per_second"]),
                "description": r["description"],
            }
            for r in rows
        ],
        disclaimer=(
            "Guessing rates are illustrative assumptions, not measurements. Actual speeds depend on "
            "hardware, hashing algorithms and rate limits."
        ),
    )
    resp.headers["Cache-Control"] = "public, max-age=60"
    return resp


@app.get("/api/tips")
def get_tips():
    category = request.args.get("category", "").strip()[:100]
    difficulty = request.args.get("difficulty", "").strip()[:50]
    sql = "SELECT tip_id, title, content, category, difficulty_level FROM security_tips"
    clauses, params = [], []
    if category:
        clauses.append("category = %s")
        params.append(category)
    if difficulty:
        clauses.append("difficulty_level = %s")
        params.append(difficulty)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)  # fixed fragments only; values are parameters
    sql += " ORDER BY tip_id ASC"
    with database.get_cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    resp = jsonify(tips=rows)
    resp.headers["Cache-Control"] = "public, max-age=60"
    return resp


# --------------------------------------------------------------------------
# Authenticated API
# --------------------------------------------------------------------------
@app.post("/api/analyses")
@limiter.limit("30 per minute")
@login_required
def save_analysis():
    data = json_body(("password_length", "estimated_entropy", "strength_category"))
    length = as_int(data.get("password_length"), "password_length", 1, 1024)
    entropy = as_entropy(data.get("estimated_entropy"))
    category = data.get("strength_category")
    if category not in STRENGTH_CATEGORIES:
        raise ApiError("strength_category is not a recognised value.")
    uid = current_user()["user_id"]
    with database.get_cursor(commit=True) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM analysis_history WHERE user_id = %s", (uid,))
        if cur.fetchone()["n"] >= MAX_ANALYSES_PER_USER:
            raise ApiError("Saved report limit reached. Delete your account data or contact the admin.", 409)
        cur.execute(
            "INSERT INTO analysis_history (user_id, password_length, estimated_entropy, strength_category) "
            "VALUES (%s, %s, %s, %s)",
            (uid, length, entropy, category),
        )
        new_id = cur.lastrowid
    return jsonify(analysis_id=new_id), 201


@app.post("/api/quiz-results")
@limiter.limit("30 per minute")
@login_required
def save_quiz_result():
    data = json_body(("score", "total_questions"))
    total = as_int(data.get("total_questions"), "total_questions", 1, 100)
    score = as_int(data.get("score"), "score", 0, total)
    uid = current_user()["user_id"]
    with database.get_cursor(commit=True) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM quiz_results WHERE user_id = %s", (uid,))
        if cur.fetchone()["n"] >= MAX_QUIZ_RESULTS_PER_USER:
            raise ApiError("Saved quiz result limit reached.", 409)
        cur.execute(
            "INSERT INTO quiz_results (user_id, score, total_questions) VALUES (%s, %s, %s)",
            (uid, score, total),
        )
        new_id = cur.lastrowid
    return jsonify(result_id=new_id), 201


@app.get("/api/history")
@login_required
def get_history():
    uid = current_user()["user_id"]
    with database.get_cursor() as cur:
        cur.execute(
            "SELECT analysis_id, password_length, estimated_entropy, strength_category, analysis_date "
            "FROM analysis_history WHERE user_id = %s "
            "ORDER BY analysis_date DESC, analysis_id DESC LIMIT 100",
            (uid,),
        )
        analyses = cur.fetchall()
        cur.execute(
            "SELECT result_id, score, total_questions, completed_at "
            "FROM quiz_results WHERE user_id = %s "
            "ORDER BY completed_at DESC, result_id DESC LIMIT 100",
            (uid,),
        )
        quizzes = cur.fetchall()
    return jsonify(
        analyses=[
            {
                "analysis_id": a["analysis_id"],
                "password_length": a["password_length"],
                "estimated_entropy": float(a["estimated_entropy"]),
                "strength_category": a["strength_category"],
                "analysis_date": iso(a["analysis_date"]),
            }
            for a in analyses
        ],
        quiz_results=[
            {
                "result_id": q["result_id"],
                "score": q["score"],
                "total_questions": q["total_questions"],
                "completed_at": iso(q["completed_at"]),
            }
            for q in quizzes
        ],
    )


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=_env_bool("FLASK_DEBUG", False),
    )
