import os
import secrets
from html import escape

from flask import Flask, request, session, make_response

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@app.get("/")
def home():
    return "Instagram OAuth callback is running."


@app.get("/auth/start")
def start():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    return (
        "<h2>OAuth state generated</h2>"
        "<p>Use this value as the state parameter "
        "in the Instagram authorization URL:</p>"
        f"<pre>{escape(state)}</pre>"
        "<p>Keep this browser session open for the callback.</p>"
    )


@app.get("/auth/callback")
def callback():
    expected = session.pop("oauth_state", None)
    received = request.args.get("state", "")

    if not expected or not secrets.compare_digest(
        expected, received
    ):
        return "Invalid OAuth state.", 403

    error = request.args.get("error")
    if error:
        return f"Authorization failed: {escape(error)}", 400

    code = request.args.get("code")
    if not code:
        return "Authorization code missing.", 400

    response = make_response(
        "<h2>Authorization successful</h2>"
        "<p>Copy this one-time code and keep it private:</p>"
        f"<pre>{escape(code)}</pre>"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response
