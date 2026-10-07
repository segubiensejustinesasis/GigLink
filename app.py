from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, abort, current_app, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._]{3,24}$")
ISLAND_GROUPS = {"Luzon", "Visayas", "Mindanao"}
MAX_PHOTO_LENGTH = 2_000_000

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    birth_date TEXT NOT NULL,
    country TEXT NOT NULL,
    island_group TEXT NOT NULL,
    region TEXT NOT NULL,
    locality TEXT NOT NULL,
    province TEXT NOT NULL,
    about TEXT NOT NULL DEFAULT '',
    skills TEXT NOT NULL DEFAULT '',
    photo TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gigs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    pay REAL NOT NULL CHECK (pay > 0),
    unit TEXT NOT NULL,
    place TEXT NOT NULL,
    time TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS gigs_created_idx ON gigs(created_at);
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gig_id INTEGER NOT NULL REFERENCES gigs(id) ON DELETE CASCADE,
    applicant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'Pending'
        CHECK (status IN ('Pending', 'Accepted', 'Declined')),
    created_at TEXT NOT NULL,
    UNIQUE (gig_id, applicant_id)
);
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    topic TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (user_a, user_b, topic),
    CHECK (user_a < user_b)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_conversation_idx
    ON messages(conversation_id, id);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    text TEXT NOT NULL,
    gig TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database = str(current_app.config["DATABASE"])
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(database)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def current_user() -> sqlite3.Row:
    user_id = session.get("user_id")
    if not isinstance(user_id, int):
        abort(401, description="Sign in to continue.")
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        session.clear()
        abort(401, description="Sign in to continue.")
    return user


def json_body() -> dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, description="Send a JSON object.")
    return body


def required_text(body: dict[str, Any], key: str, maximum: int) -> str:
    value = body.get(key)
    if not isinstance(value, str):
        abort(400, description=f"{key} is required.")
    value = value.strip()
    if not value or len(value) > maximum:
        abort(400, description=f"{key} must be between 1 and {maximum} characters.")
    return value


def user_json(user: sqlite3.Row) -> dict[str, Any]:
    locality = user["locality"]
    province = user["province"]
    region = user["region"]
    island_group = user["island_group"]
    country = user["country"]
    return {
        "id": user["id"],
        "userId": user["public_id"],
        "name": user["name"],
        "username": user["username"],
        "birthDate": user["birth_date"],
        "country": country,
        "islandGroup": island_group,
        "region": region,
        "locality": locality,
        "province": province,
        "location": ", ".join(part for part in (locality, province, region, island_group, country) if part),
        "about": user["about"],
        "skills": user["skills"],
        "photo": user["photo"],
    }


def age_on(birth_date: date, today: date | None = None) -> int:
    today = today or date.today()
    return today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, static_folder="static")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("GIGLIMK_SECRET_KEY") or secrets.token_urlsafe(32),
        DATABASE=os.environ.get("GIGLIMK_DATABASE", str(BASE_DIR / "giglimk.sqlite3")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("GIGLIMK_COOKIE_SECURE", "").lower() == "true",
        MAX_CONTENT_LENGTH=3 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        database = g.pop("db", None)
        if database is not None:
            if _error is not None:
                database.rollback()
            database.close()

    with app.app_context():
        get_db().executescript(SCHEMA)

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(413)
    def handle_http_error(error: Any) -> tuple[Any, int]:
        message = getattr(error, "description", "Request failed.")
        return jsonify(error=message), error.code

    @app.get("/")
    def index() -> Any:
        return send_from_directory(BASE_DIR, "page.html")

    @app.get("/api/health")
    def health() -> Any:
        return jsonify(status="ok")

    @app.post("/api/auth/register")
    def register() -> Any:
        body = json_body()
        name = required_text(body, "name", 60)
        username = required_text(body, "username", 24).lower()
        if not USERNAME_PATTERN.fullmatch(username):
            abort(400, description="Username must be 3–24 letters, numbers, dots, or underscores.")
        password = body.get("password")
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
            abort(400, description="Password must be between 10 and 128 characters.")
        try:
            birth_date = date.fromisoformat(required_text(body, "birthDate", 10))
        except ValueError:
            abort(400, description="Enter a valid birthday.")
        if age_on(birth_date) < 18:
            abort(400, description="You must be at least 18 years old to create an account.")
        if birth_date > date.today():
            abort(400, description="Birthday cannot be in the future.")

        country = required_text(body, "country", 60)
        island_group = required_text(body, "islandGroup", 20)
        if country != "Philippines" or island_group not in ISLAND_GROUPS:
            abort(400, description="Choose a valid Philippines location.")
        region = required_text(body, "region", 100)
        locality = required_text(body, "locality", 100)
        province = required_text(body, "province", 80)
        about = body.get("about", "")
        skills = body.get("skills", "")
        photo = body.get("photo", "")
        if not isinstance(about, str) or len(about) > 1000:
            abort(400, description="About must be at most 1,000 characters.")
        if not isinstance(skills, str) or len(skills) > 500:
            abort(400, description="Skills must be at most 500 characters.")
        if not isinstance(photo, str) or len(photo) > MAX_PHOTO_LENGTH:
            abort(400, description="Profile photo is too large.")

        database = get_db()
        for _ in range(5):
            public_id = f"GL-{secrets.randbelow(100_000_000):08d}"
            try:
                cursor = database.execute(
                    """INSERT INTO users
                       (public_id, name, username, password_hash, birth_date, country,
                        island_group, region, locality, province, about, skills, photo, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        public_id,
                        name,
                        username,
                        generate_password_hash(password),
                        birth_date.isoformat(),
                        country,
                        island_group,
                        region,
                        locality,
                        province,
                        about,
                        skills,
                        photo,
                        utc_now(),
                    ),
                )
                database.commit()
                break
            except sqlite3.IntegrityError as error:
                database.rollback()
                if "username" in str(error).lower():
                    abort(409, description="That username is already taken.")
                if "public_id" not in str(error).lower() or _ == 4:
                    raise
        else:
            abort(500, description="Could not allocate a member ID.")

        user = database.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        session.clear()
        session["user_id"] = user["id"]
        return jsonify(user=user_json(user)), 201

    @app.post("/api/auth/login")
    def login() -> Any:
        body = json_body()
        identity = required_text(body, "identity", 80).removeprefix("@")
        password = body.get("password")
        if not isinstance(password, str):
            abort(400, description="Password is required.")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR public_id = ? COLLATE NOCASE",
            (identity, identity),
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            abort(401, description="Username/member ID or password is incorrect.")
        session.clear()
        session["user_id"] = user["id"]
        return jsonify(user=user_json(user))

    @app.post("/api/auth/logout")
    def logout() -> Any:
        current_user()
        session.clear()
        return jsonify(status="ok")

    @app.get("/api/auth/me")
    def who_am_i() -> Any:
        user_id = session.get("user_id")
        if not isinstance(user_id, int):
            return jsonify(user=None)
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            session.clear()
            return jsonify(user=None)
        return jsonify(user=user_json(user))

    @app.patch("/api/profile")
    def update_profile() -> Any:
        user = current_user()
        body = json_body()
        fields: dict[str, tuple[str, int]] = {
            "name": ("name", 60),
            "username": ("username", 24),
            "islandGroup": ("island_group", 20),
            "region": ("region", 100),
            "country": ("country", 60),
            "locality": ("locality", 100),
            "province": ("province", 80),
            "about": ("about", 1000),
            "skills": ("skills", 500),
            "photo": ("photo", MAX_PHOTO_LENGTH),
        }
        changes: dict[str, str] = {}
        for key, (column, maximum) in fields.items():
            if key in body:
                value = body[key]
                if not isinstance(value, str) or len(value) > maximum:
                    abort(400, description=f"{key} is invalid or too long.")
                changes[column] = value.strip()
        username = changes.get("username")
        if username:
            username = username.removeprefix("@").lower()
            if not USERNAME_PATTERN.fullmatch(username):
                abort(400, description="Choose a valid username.")
            changes["username"] = username
        if changes.get("country", user["country"]) != "Philippines":
            abort(400, description="Country must be Philippines.")
        if changes.get("island_group", user["island_group"]) not in ISLAND_GROUPS:
            abort(400, description="Choose a valid island group.")
        if not changes:
            abort(400, description="No profile changes were provided.")
        assignments = ", ".join(f"{column} = ?" for column in changes)
        try:
            get_db().execute(
                f"UPDATE users SET {assignments} WHERE id = ?",
                (*changes.values(), user["id"]),
            )
            get_db().commit()
        except sqlite3.IntegrityError as error:
            get_db().rollback()
            if "username" in str(error).lower():
                abort(409, description="That username is already taken.")
            raise
        updated = get_db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        return jsonify(user=user_json(updated))

    @app.get("/api/gigs")
    def list_gigs() -> Any:
        user = current_user()
        rows = get_db().execute(
            """SELECT gigs.*, users.name AS owner_name,
                      (SELECT COUNT(*) FROM applications WHERE applications.gig_id = gigs.id) AS app_count
               FROM gigs JOIN users ON users.id = gigs.owner_id
               ORDER BY gigs.created_at DESC, gigs.id DESC"""
        ).fetchall()
        return jsonify(gigs=[{
            "id": row["id"],
            "title": row["title"],
            "category": row["category"],
            "pay": row["pay"],
            "unit": row["unit"],
            "place": row["place"],
            "time": row["time"],
            "desc": row["description"],
            "client": row["owner_name"],
            "rating": "New",
            "apps": row["app_count"],
            "isOwner": row["owner_id"] == user["id"],
            "icon": "✦",
            "tone": "green",
        } for row in rows])

    @app.post("/api/gigs")
    def create_gig() -> Any:
        user = current_user()
        body = json_body()
        title = required_text(body, "title", 100)
        category = required_text(body, "category", 60)
        unit = required_text(body, "unit", 20)
        if unit not in {"fixed", "per hour"}:
            abort(400, description="Choose a valid payment unit.")
        try:
            pay = float(body.get("pay"))
        except (TypeError, ValueError):
            abort(400, description="Enter a valid payment amount.")
        if not 0 < pay <= 10_000_000:
            abort(400, description="Payment must be greater than zero and no more than 10,000,000.")
        place = required_text(body, "place", 180)
        time = required_text(body, "time", 100)
        description = required_text(body, "desc", 4000)
        cursor = get_db().execute(
            """INSERT INTO gigs (owner_id, title, category, pay, unit, place, time, description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user["id"], title, category, pay, unit, place, time, description, utc_now()),
        )
        get_db().commit()
        return jsonify(id=cursor.lastrowid), 201

    @app.post("/api/gigs/<int:gig_id>/applications")
    def apply_to_gig(gig_id: int) -> Any:
        user = current_user()
        database = get_db()
        gig = database.execute("SELECT * FROM gigs WHERE id = ?", (gig_id,)).fetchone()
        if gig is None:
            abort(404, description="Gig not found.")
        if gig["owner_id"] == user["id"]:
            abort(403, description="You cannot apply to your own gig.")
        try:
            cursor = database.execute(
                "INSERT INTO applications (gig_id, applicant_id, created_at) VALUES (?, ?, ?)",
                (gig_id, user["id"], utc_now()),
            )
            database.commit()
        except sqlite3.IntegrityError:
            database.rollback()
            abort(409, description="You have already applied to this gig.")
        return jsonify(id=cursor.lastrowid, status="Pending"), 201

    @app.get("/api/applications")
    def list_applications() -> Any:
        user = current_user()
        rows = get_db().execute(
            """SELECT applications.id, applications.gig_id, applications.status,
                      applications.created_at, applications.applicant_id,
                      gigs.owner_id, gigs.title AS gig, gigs.pay, gigs.place,
                      applicant.name AS provider, applicant.username AS provider_username
               FROM applications
               JOIN gigs ON gigs.id = applications.gig_id
               JOIN users AS applicant ON applicant.id = applications.applicant_id
               WHERE gigs.owner_id = ? OR applications.applicant_id = ?
               ORDER BY applications.created_at DESC, applications.id DESC""",
            (user["id"], user["id"]),
        ).fetchall()
        return jsonify(applications=[{
            "id": row["id"],
            "gig_id": row["gig_id"],
            "gig": row["gig"],
            "provider": row["provider"],
            "username": row["provider_username"],
            "initials": "".join(part[0] for part in row["provider"].split()[:2]).upper(),
            "pay": row["pay"],
            "place": row["place"],
            "status": row["status"],
            "owner": row["owner_id"] == user["id"],
            "created_at": row["created_at"],
        } for row in rows])

    @app.patch("/api/applications/<int:application_id>")
    def update_application(application_id: int) -> Any:
        user = current_user()
        body = json_body()
        status = body.get("status")
        if status not in {"Accepted", "Declined"}:
            abort(400, description="Status must be Accepted or Declined.")
        database = get_db()
        application = database.execute(
            """SELECT applications.*, gigs.owner_id
               FROM applications JOIN gigs ON gigs.id = applications.gig_id
               WHERE applications.id = ?""",
            (application_id,),
        ).fetchone()
        if application is None:
            abort(404, description="Application not found.")
        if application["owner_id"] != user["id"]:
            abort(403, description="Only the gig owner can respond to this application.")
        if application["status"] != "Pending":
            abort(409, description="This application has already been answered.")
        database.execute(
            "UPDATE applications SET status = ? WHERE id = ?", (status, application_id)
        )
        database.commit()
        return jsonify(id=application_id, status=status)

    def conversation_json(conversation: sqlite3.Row, user_id: int) -> dict[str, Any]:
        other_id = conversation["user_b"] if conversation["user_a"] == user_id else conversation["user_a"]
        other = get_db().execute(
            "SELECT name FROM users WHERE id = ?", (other_id,)
        ).fetchone()
        message_rows = get_db().execute(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id",
            (conversation["id"],),
        ).fetchall()
        chat = []
        for message in message_rows:
            created = datetime.fromisoformat(message["created_at"]).astimezone()
            chat.append([
                "mine" if message["sender_id"] == user_id else "theirs",
                message["body"],
                created.strftime("%I:%M %p").lstrip("0"),
            ])
        latest = message_rows[-1] if message_rows else None
        latest_time = datetime.fromisoformat(latest["created_at"]).astimezone() if latest else None
        initials = "".join(part[0] for part in other["name"].split()[:2]).upper()
        return {
            "id": conversation["id"],
            "name": other["name"],
            "initials": initials,
            "tone": "blue",
            "last": latest["body"] if latest else "Start a conversation",
            "time": latest_time.strftime("%I:%M %p").lstrip("0") if latest_time else "",
            "gig": conversation["topic"],
            "chat": chat,
        }

    @app.get("/api/conversations")
    def list_conversations() -> Any:
        user = current_user()
        rows = get_db().execute(
            "SELECT * FROM conversations WHERE user_a = ? OR user_b = ? ORDER BY id DESC",
            (user["id"], user["id"]),
        ).fetchall()
        return jsonify(conversations=[conversation_json(row, user["id"]) for row in rows])

    @app.post("/api/conversations")
    def create_conversation() -> Any:
        user = current_user()
        body = json_body()
        identity = required_text(body, "name", 80).removeprefix("@")
        topic = required_text(body, "gig", 100)
        matches = get_db().execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE OR name = ? COLLATE NOCASE",
            (identity, identity),
        ).fetchall()
        if not matches:
            abort(404, description="No community member matched that username or exact name.")
        if len(matches) > 1:
            abort(409, description="More than one member has that name. Enter their username instead.")
        other_id = matches[0]["id"]
        if other_id == user["id"]:
            abort(400, description="You cannot start a conversation with yourself.")
        user_a, user_b = sorted((user["id"], other_id))
        database = get_db()
        database.execute(
            """INSERT OR IGNORE INTO conversations (user_a, user_b, topic, created_at)
               VALUES (?, ?, ?, ?)""",
            (user_a, user_b, topic, utc_now()),
        )
        database.commit()
        conversation = database.execute(
            "SELECT * FROM conversations WHERE user_a = ? AND user_b = ? AND topic = ?",
            (user_a, user_b, topic),
        ).fetchone()
        return jsonify(conversation=conversation_json(conversation, user["id"])), 201

    @app.post("/api/conversations/<int:conversation_id>/messages")
    def send_message(conversation_id: int) -> Any:
        user = current_user()
        body = json_body()
        text = required_text(body, "text", 2000)
        database = get_db()
        conversation = database.execute(
            """SELECT * FROM conversations
               WHERE id = ? AND (user_a = ? OR user_b = ?)""",
            (conversation_id, user["id"], user["id"]),
        ).fetchone()
        if conversation is None:
            abort(404, description="Conversation not found.")
        database.execute(
            "INSERT INTO messages (conversation_id, sender_id, body, created_at) VALUES (?, ?, ?, ?)",
            (conversation_id, user["id"], text, utc_now()),
        )
        database.commit()
        return jsonify(conversation=conversation_json(conversation, user["id"]))

    @app.get("/api/reviews")
    def list_reviews() -> Any:
        user = current_user()
        rows = get_db().execute(
            """SELECT reviews.*, users.name AS author
               FROM reviews JOIN users ON users.id = reviews.author_id
               ORDER BY reviews.id DESC"""
        ).fetchall()
        return jsonify(reviews=[{
            "author": row["author"],
            "rating": row["rating"],
            "text": row["text"],
            "gig": row["gig"],
            "date": datetime.fromisoformat(row["created_at"]).astimezone().strftime("%b %d, %Y").replace(" 0", " "),
            "isMine": row["author_id"] == user["id"],
        } for row in rows])

    @app.post("/api/reviews")
    def create_review() -> Any:
        user = current_user()
        body = json_body()
        rating = body.get("rating")
        if isinstance(rating, bool) or not isinstance(rating, int) or not 1 <= rating <= 5:
            abort(400, description="Rating must be a whole number from 1 to 5.")
        text = required_text(body, "text", 500)
        gig = required_text(body, "gig", 100)
        database = get_db()
        cursor = database.execute(
            "INSERT INTO reviews (author_id, rating, text, gig, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], rating, text, gig, utc_now()),
        )
        database.commit()
        return jsonify(id=cursor.lastrowid), 201

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
