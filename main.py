from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import httpx
from fastapi import Body, Cookie, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

# =============================================================================
# Vaultline - main.py
# =============================================================================

APP_NAME = "Vaultline"

# ---------------------------------------------------------------------------
# Fixed configuration requested for this project
# ---------------------------------------------------------------------------

BASE_URL = "https://vautlinemainframe.onrender.com"

DISCORD_REDIRECT_URI = (
    "https://vautlinemainframe.onrender.com/auth/discord/callback"
)

DISCORD_CLIENT_ID = "1551993849101025370"
DISCORD_CLIENT_SECRET = os.getenv(
    "DISCORD_CLIENT_SECRET",
    "hier_ein_fallback",
)

ADMIN_IDS = {
    "1530358349323964476",
}

TELEGRAM_BOT_TOKEN = (
    "8835437959:AAFKxE8yAfMjzqT58b-oaGrqFLG2kCIo__Q"
)

UNBELIEVABOAT_API_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJhcHBfaWQiOiIxNTUyMDAxMzg1NTQzODk0NzA4IiwiaWF0IjoxNzkwMDk2MzY1fQ."
    "f9vA84aXjtwkp6qTvOpLmi8IgBECMtpZ5_gFxVYZ1F4"
)

GUILD_ID = os.getenv(
    "GUILD_ID",
    "deine_guild_id",
)

# Optional Render environment variable.
# It is used to sign login sessions and OAuth state.
# Falling back to the Discord client secret avoids another hard-coded secret.
APP_SECRET_KEY = os.getenv(
    "APP_SECRET_KEY",
    DISCORD_CLIENT_SECRET,
)

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"

UNBELIEVABOAT_BASE = (
    "https://unbelievaboat.com/api/v1"
)

TELEGRAM_API_BASE = (
    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
)

TELEGRAM_WEBHOOK_PATH = (
    f"/telegram/webhook/{TELEGRAM_BOT_TOKEN}"
)

# ---------------------------------------------------------------------------
# Local settings
# ---------------------------------------------------------------------------

DATABASE_PATH = (
    Path(__file__).resolve().parent / "vaultline.db"
)

SESSION_COOKIE_NAME = "vaultline_session"
OAUTH_STATE_COOKIE_NAME = "vaultline_oauth_state"

SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
OAUTH_STATE_TTL_SECONDS = 10 * 60

HTTP_TIMEOUT = httpx.Timeout(
    15.0,
    connect=5.0,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(APP_NAME)


# =============================================================================
# SQLite
# =============================================================================

def get_db() -> sqlite3.Connection:
    """
    Open a short-lived SQLite connection.

    SQLite is configured for:
    - WAL mode
    - foreign keys
    - a busy timeout
    """

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
        isolation_level=None,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")

    return connection


def init_db() -> None:
    """
    Create the Vaultline users table.
    """

    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                discord_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                balance INTEGER NOT NULL DEFAULT 100,
                telegram_chat_id TEXT
            )
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_users_telegram_chat_id
            ON users(telegram_chat_id)
            """
        )


def upsert_user(
    discord_id: str,
    username: str,
) -> sqlite3.Row:
    """
    Create a user if necessary or update their username.

    Existing balances and Telegram links are preserved.
    """

    with get_db() as db:
        db.execute(
            """
            INSERT INTO users (
                discord_id,
                username,
                balance
            )
            VALUES (?, ?, 100)

            ON CONFLICT(discord_id)
            DO UPDATE SET
                username = excluded.username
            """,
            (
                discord_id,
                username,
            ),
        )

        row = db.execute(
            """
            SELECT
                discord_id,
                username,
                balance,
                telegram_chat_id
            FROM users
            WHERE discord_id = ?
            """,
            (discord_id,),
        ).fetchone()

    if row is None:
        raise RuntimeError(
            "User was not available after database upsert."
        )

    return row


def get_user(
    discord_id: str,
) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(
            """
            SELECT
                discord_id,
                username,
                balance,
                telegram_chat_id
            FROM users
            WHERE discord_id = ?
            """,
            (discord_id,),
        ).fetchone()


def get_user_by_telegram_chat_id(
    chat_id: str,
) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(
            """
            SELECT
                discord_id,
                username,
                balance,
                telegram_chat_id
            FROM users
            WHERE telegram_chat_id = ?
            LIMIT 1
            """,
            (chat_id,),
        ).fetchone()


def set_telegram_chat_id(
    discord_id: str,
    chat_id: str,
) -> None:
    with get_db() as db:
        db.execute(
            """
            UPDATE users
            SET telegram_chat_id = ?
            WHERE discord_id = ?
            """,
            (
                chat_id,
                discord_id,
            ),
        )


# =============================================================================
# Signed session / OAuth state helpers
# =============================================================================

def _hmac_signature(value: str) -> str:
    digest = hmac.new(
        APP_SECRET_KEY.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return (
        base64.urlsafe_b64encode(digest)
        .decode("ascii")
        .rstrip("=")
    )


def _make_signed_value(
    payload: dict[str, Any],
) -> str:
    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    encoded = (
        base64.urlsafe_b64encode(raw)
        .decode("ascii")
        .rstrip("=")
    )

    signature = _hmac_signature(encoded)

    return f"{encoded}.{signature}"


def _read_signed_value(
    value: str,
) -> dict[str, Any] | None:
    try:
        encoded, signature = value.rsplit(".", 1)

        expected_signature = _hmac_signature(encoded)

        if not hmac.compare_digest(
            signature,
            expected_signature,
        ):
            return None

        padded = encoded + "=" * (-len(encoded) % 4)

        payload = json.loads(
            base64.urlsafe_b64decode(padded)
            .decode("utf-8")
        )

        if not isinstance(payload, dict):
            return None

        return payload

    except (
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        return None


def create_oauth_state() -> str:
    return _make_signed_value(
        {
            "nonce": secrets.token_urlsafe(32),
            "exp": int(time.time())
            + OAUTH_STATE_TTL_SECONDS,
        }
    )


def validate_oauth_state(
    value: str | None,
) -> bool:
    if not value:
        return False

    payload = _read_signed_value(value)

    if not payload:
        return False

    try:
        nonce = str(payload["nonce"])
        expiration = int(payload["exp"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return False

    return (
        bool(nonce)
        and time.time() < expiration
    )


def create_session(
    discord_id: str,
) -> str:
    return _make_signed_value(
        {
            "discord_id": discord_id,
            "exp": int(time.time())
            + SESSION_TTL_SECONDS,
        }
    )


def get_session_discord_id(
    session_cookie: str | None,
) -> str | None:
    if not session_cookie:
        return None

    payload = _read_signed_value(session_cookie)

    if not payload:
        return None

    try:
        discord_id = str(payload["discord_id"])
        expiration = int(payload["exp"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None

    if not discord_id:
        return None

    if time.time() >= expiration:
        return None

    return discord_id


def is_admin(
    discord_id: str,
) -> bool:
    return discord_id in ADMIN_IDS


# =============================================================================
# Authentication helpers
# =============================================================================

def require_user(
    session_cookie: str | None,
) -> sqlite3.Row:
    discord_id = get_session_discord_id(
        session_cookie
    )

    if not discord_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = get_user(discord_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found",
        )

    return user


def require_admin(
    session_cookie: str | None,
) -> sqlite3.Row:
    user = require_user(session_cookie)

    if not is_admin(
        str(user["discord_id"])
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required",
        )

    return user


# =============================================================================
# Discord OAuth2
# =============================================================================

async def exchange_discord_code(
    client: httpx.AsyncClient,
    code: str,
) -> dict[str, Any]:
    """
    Exchange the Discord OAuth2 authorization code
    for an access token.
    """

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }

    try:
        response = await client.post(
            DISCORD_TOKEN_URL,
            data=data,
            auth=(
                DISCORD_CLIENT_ID,
                DISCORD_CLIENT_SECRET,
            ),
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded",
            },
        )

    except httpx.HTTPError as exc:
        logger.exception(
            "Discord token exchange failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=502,
            detail="Discord authentication unavailable",
        ) from exc

    if response.status_code != 200:
        logger.warning(
            "Discord token exchange returned HTTP %s",
            response.status_code,
        )

        raise HTTPException(
            status_code=502,
            detail="Discord authentication failed",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Discord returned invalid JSON",
        ) from exc

    if not payload.get("access_token"):
        raise HTTPException(
            status_code=502,
            detail="Discord did not return an access token",
        )

    return payload


async def get_discord_user(
    client: httpx.AsyncClient,
    access_token: str,
) -> dict[str, Any]:
    """
    Retrieve the authenticated Discord user.
    """

    try:
        response = await client.get(
            f"{DISCORD_API_BASE}/users/@me",
            headers={
                "Authorization":
                    f"Bearer {access_token}",
            },
        )

    except httpx.HTTPError as exc:
        logger.exception(
            "Discord user lookup failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=502,
            detail="Discord user lookup unavailable",
        ) from exc

    if response.status_code != 200:
        logger.warning(
            "Discord user lookup returned HTTP %s",
            response.status_code,
        )

        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve Discord user",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Discord returned invalid JSON",
        ) from exc

    if (
        not payload.get("id")
        or not payload.get("username")
    ):
        raise HTTPException(
            status_code=502,
            detail="Discord returned incomplete user data",
        )

    return payload


# =============================================================================
# UnbelievaBoat
# =============================================================================

class BalancePatch(BaseModel):
    """
    PATCH body for UnbelievaBoat.

    According to the current UnbelievaBoat API documentation,
    cash and bank are accepted balance changes.
    """

    cash: int | None = Field(
        default=None,
        description="Cash delta",
    )

    bank: int | None = Field(
        default=None,
        description="Bank delta",
    )

    reason: str | None = Field(
        default=None,
        max_length=500,
    )

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}

        if self.cash is not None:
            payload["cash"] = self.cash

        if self.bank is not None:
            payload["bank"] = self.bank

        if self.reason:
            payload["reason"] = self.reason

        return payload


def unbelievaboat_user_url(
    user_id: str,
) -> str:
    guild_id = quote(
        str(GUILD_ID),
        safe="",
    )

    discord_user_id = quote(
        str(user_id),
        safe="",
    )

    return (
        f"{UNBELIEVABOAT_BASE}"
        f"/guilds/{guild_id}"
        f"/users/{discord_user_id}"
    )


def ub_headers() -> dict[str, str]:
    return {
        "Authorization":
            f"Bearer {UNBELIEVABOAT_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Vaultline/1.0",
    }


async def get_unbelievaboat_balance(
    client: httpx.AsyncClient,
    user_id: str,
) -> dict[str, Any]:
    """
    GET:
    /guilds/{guild_id}/users/{user_id}
    """

    try:
        response = await client.get(
            unbelievaboat_user_url(user_id),
            headers=ub_headers(),
        )

    except httpx.HTTPError as exc:
        logger.exception(
            "UnbelievaBoat GET failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=502,
            detail="UnbelievaBoat API unavailable",
        ) from exc

    if response.status_code != 200:
        logger.warning(
            "UnbelievaBoat GET returned HTTP %s",
            response.status_code,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "UnbelievaBoat returned "
                f"HTTP {response.status_code}"
            ),
        )

    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="UnbelievaBoat returned invalid JSON",
        ) from exc


async def patch_unbelievaboat_balance(
    client: httpx.AsyncClient,
    user_id: str,
    patch: BalancePatch,
) -> dict[str, Any]:
    """
    PATCH:
    /guilds/{guild_id}/users/{user_id}
    """

    payload = patch.to_payload()

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Provide at least one of "
                "'cash' or 'bank'"
            ),
        )

    try:
        response = await client.patch(
            unbelievaboat_user_url(user_id),
            headers=ub_headers(),
            json=payload,
        )

    except httpx.HTTPError as exc:
        logger.exception(
            "UnbelievaBoat PATCH failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=502,
            detail="UnbelievaBoat API unavailable",
        ) from exc

    if response.status_code != 200:
        logger.warning(
            "UnbelievaBoat PATCH returned HTTP %s",
            response.status_code,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "UnbelievaBoat returned "
                f"HTTP {response.status_code}"
            ),
        )

    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="UnbelievaBoat returned invalid JSON",
        ) from exc


# =============================================================================
# Telegram
# =============================================================================

async def telegram_send_message(
    client: httpx.AsyncClient,
    chat_id: str | int,
    text: str,
) -> None:
    """
    Send a text message through the Telegram Bot API.
    """

    try:
        response = await client.post(
            f"{TELEGRAM_API_BASE}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
            },
        )

        if response.status_code != 200:
            logger.warning(
                "Telegram sendMessage returned HTTP %s",
                response.status_code,
            )

    except httpx.HTTPError as exc:
        logger.warning(
            "Telegram sendMessage failed: %s",
            exc,
        )


async def process_telegram_update(
    client: httpx.AsyncClient,
    update: dict[str, Any],
) -> None:
    """
    Minimal safe Telegram update handler.

    Supported:
      /start
      /help
      /status

    Account linking can be added later without exposing
    Discord IDs directly through a public command.
    """

    message = update.get("message")

    if not isinstance(message, dict):
        return

    chat = message.get("chat")

    if not isinstance(chat, dict):
        return

    if "id" not in chat:
        return

    chat_id = chat["id"]

    message_text = message.get("text")

    if not isinstance(message_text, str):
        return

    command = (
        message_text
        .strip()
        .split(maxsplit=1)[0]
        .lower()
    )

    if command in {
        "/start",
        "/help",
    }:
        await telegram_send_message(
            client,
            chat_id,
            (
                "Vaultline verbunden.\n"
                "Für die Kontoverknüpfung nutze das "
                "Vaultline-Webinterface."
            ),
        )
        return

    if command == "/status":
        user = get_user_by_telegram_chat_id(
            str(chat_id)
        )

        if user is None:
            await telegram_send_message(
                client,
                chat_id,
                (
                    "Dieser Telegram-Chat ist noch "
                    "keinem Vaultline-Konto zugeordnet."
                ),
            )
            return

        await telegram_send_message(
            client,
            chat_id,
            (
                f"Vaultline-Konto: {user['username']}\n"
                f"Lokales Guthaben: {user['balance']}"
            ),
        )


# =============================================================================
# FastAPI lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()

    application.state.http_client = (
        httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            headers={
                "User-Agent":
                    "Vaultline/1.0",
            },
            follow_redirects=False,
        )
    )

    logger.info(
        "Vaultline started. Database: %s",
        DATABASE_PATH,
    )

    try:
        yield
    finally:
        await application.state.http_client.aclose()

        logger.info(
            "Vaultline stopped."
        )


app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    description=(
        "Vaultline authentication and "
        "economy backend."
    ),
    lifespan=lifespan,
)


# =============================================================================
# Basic routes
# =============================================================================

@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "status": "online",
        "auth": "/auth/discord",
        "health": "/health",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
    }


# =============================================================================
# Discord OAuth2
# =============================================================================

@app.get("/auth/discord")
async def discord_login() -> RedirectResponse:
    """
    Start Discord OAuth2 login.
    """

    state = create_oauth_state()

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": "identify",
        "state": state,
    }

    authorization_url = (
        f"{DISCORD_AUTHORIZE_URL}"
        f"?{urlencode(params)}"
    )

    response = RedirectResponse(
        url=authorization_url,
        status_code=status.HTTP_302_FOUND,
    )

    response.set_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        value=state,
        max_age=OAUTH_STATE_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/auth/discord",
    )

    return response


@app.get("/auth/discord/callback")
async def discord_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    vaultline_oauth_state: str | None = Cookie(
        default=None,
        alias=OAUTH_STATE_COOKIE_NAME,
    ),
) -> RedirectResponse:
    """
    Discord OAuth2 callback.
    """

    if error:
        logger.info(
            "Discord OAuth returned error=%s",
            error,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Discord authorization was "
                "cancelled or rejected"
            ),
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing OAuth code or state",
        )

    # Prevent CSRF / login injection.
    if (
        not vaultline_oauth_state
        or not hmac.compare_digest(
            state,
            vaultline_oauth_state,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state",
        )

    if not validate_oauth_state(
        vaultline_oauth_state
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expired OAuth state",
        )

    # Exchange authorization code.
    token_payload = await exchange_discord_code(
        request.app.state.http_client,
        code,
    )

    access_token = str(
        token_payload["access_token"]
    )

    # Retrieve Discord identity.
    discord_user = await get_discord_user(
        request.app.state.http_client,
        access_token,
    )

    discord_id = str(
        discord_user["id"]
    )

    username = str(
        discord_user.get("global_name")
        or discord_user["username"]
    )

    # Persist user.
    upsert_user(
        discord_id,
        username,
    )

    # Admin -> /admin
    # Normal user -> /dashboard
    destination = (
        "/admin"
        if is_admin(discord_id)
        else "/dashboard"
    )

    response = RedirectResponse(
        url=destination,
        status_code=status.HTTP_302_FOUND,
    )

    response.delete_cookie(
        OAUTH_STATE_COOKIE_NAME,
        path="/auth/discord",
    )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session(discord_id),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    return response


@app.post("/auth/logout")
async def logout() -> JSONResponse:
    response = JSONResponse(
        {
            "ok": True,
        }
    )

    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
    )

    return response


# =============================================================================
# Dashboard
# =============================================================================

@app.get("/dashboard")
async def dashboard(
    vaultline_session: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
) -> dict[str, Any]:
    user = require_user(
        vaultline_session
    )

    return {
        "page": "dashboard",
        "user": {
            "discord_id":
                user["discord_id"],
            "username":
                user["username"],
            "balance":
                user["balance"],
            "telegram_chat_id":
                user["telegram_chat_id"],
        },
    }


# =============================================================================
# Admin
# =============================================================================

@app.get("/admin")
async def admin(
    vaultline_session: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
) -> dict[str, Any]:
    user = require_admin(
        vaultline_session
    )

    return {
        "page": "admin",
        "user": {
            "discord_id":
                user["discord_id"],
            "username":
                user["username"],
        },
        "guild_id_configured":
            GUILD_ID != "deine_guild_id",
    }


# =============================================================================
# UnbelievaBoat API routes
# =============================================================================

@app.get("/api/unbelievaboat/me/balance")
async def unbelievaboat_my_balance(
    request: Request,
    vaultline_session: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
) -> dict[str, Any]:
    """
    Return the authenticated user's
    UnbelievaBoat balance.
    """

    user = require_user(
        vaultline_session
    )

    data = await get_unbelievaboat_balance(
        request.app.state.http_client,
        str(user["discord_id"]),
    )

    return {
        "discord_id":
            user["discord_id"],
        "unbelievaboat":
            data,
    }


@app.patch(
    "/api/admin/unbelievaboat/users/{user_id}/balance"
)
async def unbelievaboat_admin_patch_balance(
    request: Request,
    user_id: str,
    patch: BalancePatch = Body(...),
    vaultline_session: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
) -> dict[str, Any]:
    """
    Admin-only UnbelievaBoat balance modification.
    """

    require_admin(
        vaultline_session
    )

    data = await patch_unbelievaboat_balance(
        request.app.state.http_client,
        user_id,
        patch,
    )

    return {
        "discord_id":
            user_id,
        "unbelievaboat":
            data,
    }


# =============================================================================
# Telegram webhook
# =============================================================================

@app.post(
    TELEGRAM_WEBHOOK_PATH,
    include_in_schema=False,
)
async def telegram_webhook(
    request: Request,
) -> dict[str, bool]:
    """
    Telegram Bot API webhook endpoint.

    Exact path:
    /telegram/webhook/8835437959:AAFKxE8yAfMjzqT58b-oaGrqFLG2kCIo__Q
    """

    try:
        update = await request.json()

    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON",
        ) from exc

    if not isinstance(update, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Telegram update must be "
                "a JSON object"
            ),
        )

    await process_telegram_update(
        request.app.state.http_client,
        update,
    )

    return {
        "ok": True,
    }


# =============================================================================
# Render entry point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    port = int(
        os.getenv(
            "PORT",
            "10000",
        )
    )

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
    )
