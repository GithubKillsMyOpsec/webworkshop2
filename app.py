from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, make_response, redirect, render_template, request, url_for

app = Flask(__name__)

SESSION_COOKIE = "demo_session"
SESSION_TTL_SECONDS = 60 * 60
BOARD_ROTATE_SECONDS = 5 * 60
BOARD_USER = "CookieBandit"

sessions: dict[str, dict[str, int | str]] = {}
board_state = {"token": "", "expires_at": 0}


def now_ts() -> int:
    return int(time.time())


def format_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def prune_sessions() -> None:
    now = now_ts()
    expired = [token for token, data in sessions.items() if data["expires_at"] <= now]
    for token in expired:
        sessions.pop(token, None)


def create_session(username: str, password: str, ttl_seconds: int) -> tuple[str, int]:
    token_seed = f"{username}:{password}".encode("utf-8")
    token = hashlib.sha256(token_seed).hexdigest()
    expires_at = now_ts() + ttl_seconds
    sessions[token] = {"username": username, "expires_at": expires_at}
    return token, expires_at


def get_session(token: str | None) -> dict[str, int | str] | None:
    if not token:
        return None
    session = sessions.get(token)
    if not session:
        return None
    if session["expires_at"] <= now_ts():
        sessions.pop(token, None)
        return None
    return session


def ensure_board_session() -> tuple[str, int]:
    now = now_ts()
    if board_state["token"] and board_state["expires_at"] > now:
        token = board_state["token"]
        expires_at = board_state["expires_at"]
    else:
        expires_at = now + BOARD_ROTATE_SECONDS
        token_seed = f"{BOARD_USER}:{expires_at}".encode("utf-8")
        token = hashlib.sha256(token_seed).hexdigest()
        board_state["token"] = token
        board_state["expires_at"] = expires_at
    sessions[token] = {"username": BOARD_USER, "expires_at": expires_at}
    return token, expires_at


def login_required(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return handler(*args, **kwargs)

    return wrapper


@app.before_request
def load_context() -> None:
    prune_sessions()
    board_token, board_expires_at = ensure_board_session()
    g.board_token = board_token
    g.board_expires_at = board_expires_at
    g.user = None
    session = get_session(request.cookies.get(SESSION_COOKIE))
    if session:
        g.user = session["username"]


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user")}


@app.route("/")
def home():
    return render_template(
        "index.html",
        session_cookie=request.cookies.get(SESSION_COOKIE),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "Please enter both a username and a password."
        else:
            token, _ = create_session(username, password, SESSION_TTL_SECONDS)
            resp = make_response(redirect(request.args.get("next") or url_for("home")))
            resp.set_cookie(
                SESSION_COOKIE,
                token,
                max_age=SESSION_TTL_SECONDS,
                samesite="Lax",
                httponly=False,
            )
            return resp
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie(SESSION_COOKIE, "", expires=0)
    return resp


@app.route("/board")
def board():
    seconds_left = max(0, g.board_expires_at - now_ts())
    minutes_left = seconds_left // 60
    remainder_seconds = seconds_left % 60
    return render_template(
        "board.html",
        board_cookie=g.board_token,
        board_expires_at=format_ts(g.board_expires_at),
        minutes_left=minutes_left,
        seconds_left=remainder_seconds,
        board_user=BOARD_USER,
    )


@app.route("/lounge")
@login_required
def lounge():
    return render_template("lounge.html")


@app.route("/secret")
@login_required
def secret():
    return render_template(
        "secret.html",
        secret_user=g.user,
        board_user=BOARD_USER,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
