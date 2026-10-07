# Giglimk

Giglimk is a local-work marketplace with a Flask and SQLite backend. The backend
serves the website and provides persistent accounts, gigs, applications,
conversations, messages, and reviews.

## Run locally

1. Create and activate a Python virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start the site with `python app.py`.
4. Open <http://127.0.0.1:5000>.

The SQLite database is created as `giglimk.sqlite3` in this folder. Set
`GIGLIMK_DATABASE` to use another database path. Set `GIGLIMK_SECRET_KEY` to a
long, random value before deploying; set `GIGLIMK_COOKIE_SECURE=true` when the
site is served over HTTPS.

New accounts must be at least 18 and use a password of 10 or more characters.
The local demo data is not imported into the shared database.

## API

- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`,
  `GET /api/auth/me`
- `GET /api/gigs`, `POST /api/gigs`,
  `POST /api/gigs/<id>/applications`
- `GET /api/applications`, `PATCH /api/applications/<id>`
- `GET /api/conversations`, `POST /api/conversations`,
  `POST /api/conversations/<id>/messages`
- `GET /api/reviews`, `POST /api/reviews`
- `GET /api/health`

API request and response bodies use JSON. Login state is held in a
server-signed, HttpOnly session cookie.
