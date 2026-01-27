from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, g, make_response, redirect, render_template, request, url_for

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

SESSION_COOKIE = "ctf_session"
FLAG_COOKIE = "ctf_flag"
SESSION_TTL_SECONDS = 60 * 60
POST_MAX_LENGTH = 4000

FLAG = os.getenv("CTF_FLAG", "flag{cookie_circus_training}")
BOT_USERNAME = os.getenv("BOT_USERNAME", "moderator")
BOT_PASSWORD = os.getenv("BOT_PASSWORD", "moderator-pass")
BOT_VISIT_SECONDS = int(os.getenv("BOT_VISIT_SECONDS", "6"))
BOT_PAGELOAD_TIMEOUT = int(os.getenv("BOT_PAGELOAD_TIMEOUT", "8"))
BOT_ENABLED = os.getenv("BOT_ENABLED", "1") != "0"
BOT_DEBUG = os.getenv("BOT_DEBUG", "0") == "1"
CTF_BASE_URL = os.getenv("CTF_BASE_URL", "http://127.0.0.1:8082")

users: dict[str, dict[str, str]] = {}
sessions: dict[str, dict[str, int | str]] = {}
posts: dict[int, dict[str, int | str]] = {}
reports: dict[int, dict[str, int | str]] = {}
bot_debug: dict[int, list[dict[str, int | str]]] = {}

post_counter = 0
report_counter = 0
lock = threading.RLock()


def now_ts() -> int:
    return int(time.time())


def format_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_session(username: str, ttl_seconds: int) -> tuple[str, int]:
    with lock:
        token = secrets.token_urlsafe(24)
        expires_at = now_ts() + ttl_seconds
        sessions[token] = {"username": username, "expires_at": expires_at}
    return token, expires_at


def get_session(token: str | None) -> dict[str, int | str] | None:
    if not token:
        return None
    with lock:
        session = sessions.get(token)
        if not session:
            return None
        if session["expires_at"] <= now_ts():
            sessions.pop(token, None)
            return None
        return session


def prune_sessions() -> None:
    now = now_ts()
    with lock:
        expired = [token for token, data in sessions.items() if data["expires_at"] <= now]
        for token in expired:
            sessions.pop(token, None)


def ensure_bot_user() -> None:
    with lock:
        if BOT_USERNAME not in users:
            users[BOT_USERNAME] = {"password": hash_password(BOT_PASSWORD)}


def next_post_id() -> int:
    global post_counter
    with lock:
        post_counter += 1
        return post_counter


def next_report_id() -> int:
    global report_counter
    with lock:
        report_counter += 1
        return report_counter


def record_bot_debug(report_id: int, message: str) -> None:
    if not BOT_DEBUG:
        return
    with lock:
        bot_debug.setdefault(report_id, []).append(
            {"created_at": now_ts(), "message": message[:400]}
        )


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
    ensure_bot_user()
    g.user = None
    session = get_session(request.cookies.get(SESSION_COOKIE))
    if session:
        g.user = session["username"]


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user")}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "Please enter a username and password."
        elif username == BOT_USERNAME:
            error = "That username is reserved for the bot."
        else:
            hashed = hash_password(password)
            with lock:
                existing = users.get(username)
                if existing and existing["password"] != hashed:
                    error = "Wrong password for that username."
                else:
                    users[username] = {"password": hashed}
                    token, _ = create_session(username, SESSION_TTL_SECONDS)
                    resp = make_response(redirect(request.args.get("next") or url_for("board")))
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
@login_required
def board():
    with lock:
        user_posts = [post for post in posts.values() if post["owner"] == g.user]
        user_reports = [report for report in reports.values() if report["owner"] == g.user]
        report_debug = {rid: bot_debug.get(rid, []) for rid in [r["id"] for r in user_reports]} if BOT_DEBUG else {}
    user_posts.sort(key=lambda item: item["created_at"], reverse=True)
    user_reports.sort(key=lambda item: item["created_at"], reverse=True)
    return render_template(
        "board.html",
        posts=user_posts,
        reports=user_reports,
        report_debug=report_debug,
        debug_enabled=BOT_DEBUG,
        post_max_length=POST_MAX_LENGTH,
        format_ts=format_ts,
    )


@app.route("/posts", methods=["POST"])
@login_required
def create_post():
    content = request.form.get("content", "")
    content = content.strip()
    if not content:
        return redirect(url_for("board"))
    if len(content) > POST_MAX_LENGTH:
        content = content[:POST_MAX_LENGTH]
    with lock:
        post_id = next_post_id()
        posts[post_id] = {
            "id": post_id,
            "owner": g.user,
            "content": content,
            "created_at": now_ts(),
        }
    return redirect(url_for("view_post", post_id=post_id))


@app.route("/posts/<int:post_id>")
@login_required
def view_post(post_id: int):
    with lock:
        post = posts.get(post_id)
    if not post or post["owner"] != g.user:
        abort(404)
    return render_template("post.html", post=post, format_ts=format_ts)


@app.route("/posts/<int:post_id>/report", methods=["POST"])
@login_required
def report_post(post_id: int):
    with lock:
        post = posts.get(post_id)
        if not post or post["owner"] != g.user:
            abort(404)
        report_id = next_report_id()
        token = secrets.token_urlsafe(18)
        reports[report_id] = {
            "id": report_id,
            "post_id": post_id,
            "owner": g.user,
            "token": token,
            "status": "queued",
            "created_at": now_ts(),
            "visited_at": 0,
            "error": "",
        }
    enqueue_report(report_id)
    return redirect(url_for("board"))


@app.route("/_review/<int:post_id>")
def review_post(post_id: int):
    token = request.args.get("token", "")
    rid = request.args.get("rid", "")
    if not token or not rid:
        abort(404)
    try:
        report_id = int(rid)
    except ValueError:
        abort(404)
    session = get_session(request.cookies.get(SESSION_COOKIE))
    if not session or session["username"] != BOT_USERNAME:
        abort(404)
    with lock:
        report = reports.get(report_id)
        post = posts.get(post_id)
    if not report or not post:
        abort(404)
    if report["post_id"] != post_id or report["token"] != token:
        abort(404)
    return render_template("review.html", post=post, report_id=report_id, format_ts=format_ts)



def enqueue_report(report_id: int) -> None:
    if not BOT_ENABLED:
        with lock:
            report = reports.get(report_id)
            if report:
                report["status"] = "bot-disabled"
        return
    thread = threading.Thread(target=process_report, args=(report_id,), daemon=True)
    thread.start()


def process_report(report_id: int) -> None:
    record_bot_debug(report_id, "Bot queued.")
    with lock:
        report = reports.get(report_id)
        if not report or report["status"] != "queued":
            return
        report["status"] = "visiting"
    try:
        record_bot_debug(report_id, "Bot launching headless Firefox.")
        session_token, _ = create_session(BOT_USERNAME, SESSION_TTL_SECONDS)
        review_url = f"{CTF_BASE_URL}/_review/{report['post_id']}?rid={report_id}&token={report['token']}"
        debug_lines = run_bot(review_url, session_token)
        for line in debug_lines:
            record_bot_debug(report_id, line)
        with lock:
            report = reports.get(report_id)
            if report:
                report["status"] = "visited"
                report["visited_at"] = now_ts()
    except Exception as exc:  # noqa: BLE001 - keep bot failures non-fatal
        with lock:
            report = reports.get(report_id)
            if report:
                report["status"] = "error"
                report["error"] = str(exc)[:200]
        record_bot_debug(report_id, f"Bot error: {exc}")


def run_bot(review_url: str, session_token: str) -> list[str]:
    print("Running bot for URL:", review_url)
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FirefoxOptions

    options = FirefoxOptions()
    options.add_argument("-headless")
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.dir", "/tmp")
    options.set_preference("browser.download.manager.showWhenStarting", False)
    options.set_preference("browser.download.manager.useWindow", False)
    options.set_preference("browser.download.manager.closeWhenDone", True)
    options.set_preference(
        "browser.helperApps.neverAsk.saveToDisk",
        "application/octet-stream,application/pdf,application/zip,application/x-msdownload",
    )
    options.set_preference("pdfjs.disabled", True)
    options.set_preference("browser.safebrowsing.downloads.enabled", True)
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("permissions.default.image", 2)
    options.set_preference("media.autoplay.default", 5)
    options.set_preference("dom.disable_open_during_load", True)

    driver = webdriver.Firefox(options=options)
    debug_lines: list[str] = []
    try:
        driver.set_page_load_timeout(BOT_PAGELOAD_TIMEOUT)
        driver.get(f"{CTF_BASE_URL}/")
        driver.add_cookie({
            "name": SESSION_COOKIE,
            "value": session_token,
            "path": "/",
            "httpOnly": False,
        })
        driver.add_cookie({
            "name": FLAG_COOKIE,
            "value": FLAG,
            "path": "/",
            "httpOnly": False,
        })
        driver.get(review_url)
        try:
            ready_state = driver.execute_script("return document.readyState")
            debug_lines.append(f"readyState={ready_state}")
            debug_lines.append(f"url={driver.current_url}")
            debug_lines.append(f"title={driver.title}")
            cookie_string = driver.execute_script("return document.cookie || ''")
            names = []
            for part in cookie_string.split(";"):
                if "=" in part:
                    name = part.split("=", 1)[0].strip()
                    if name:
                        names.append(name)
            debug_lines.append(f"cookie_names={','.join(sorted(set(names)))}")
            debug_lines.append(f"cookie_length={len(cookie_string)}")
            debug_lines.append("images_disabled=true")
        except Exception as exc:  # noqa: BLE001 - keep debug optional
            debug_lines.append(f"debug_error={exc}")
        time.sleep(BOT_VISIT_SECONDS)
    finally:
        driver.quit()
    return debug_lines


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=False, threaded=True)
