# College Management Portal (secure web app)

Roles: **student** (view own marks), **faculty** (add marks), **admin** (create users).

## Run locally
    pip install -r requirements.txt
    APP_ENV=dev DEMO_PASSWORD='Demo@12345' python app.py     # http://127.0.0.1:5000
Users: admin / faculty1 / student1 (password = DEMO_PASSWORD).

## Deploy (Render.com, free)
1. Push this folder to a GitHub repo.
2. Render -> New -> Web Service -> select repo.
3. Build: `pip install -r requirements.txt`  Start: `gunicorn app:app`
4. Environment variables: `SECRET_KEY` (long random string), `DEMO_PASSWORD` (e.g. Demo@12345), `APP_ENV=production`
5. Share the `https://...onrender.com` URL.

## Security principles -> where applied (app.py)
| Principle | Implementation |
|---|---|
| Architecture / deployment | Single trust boundary, gunicorn behind HTTPS (Render), debug off |
| Input validation | Regex allow-lists, int/range checks, size limit, parameterized SQL |
| Authentication | Salted password hashes, strong password policy, lockout after 5 fails, generic errors |
| Authorization | Role-based `login_required(role)` decorator, deny by default |
| Configuration management | `SECRET_KEY`, DB path, env from environment; app refuses to start without key in production |
| Sensitive data | No plaintext passwords; no secrets in code or logs; no-store cache header |
| Session management | HttpOnly, Secure, SameSite cookies; 15 min idle timeout; session reset on login; CSRF tokens |
| Cryptography | PBKDF2/scrypt hashing (werkzeug), HMAC compare, HTTPS + HSTS |
| Parameter manipulation | `/marks/<id>` checks id == session user (IDOR blocked); server-side validation of form fields |
| Exception management | Generic error pages; stack traces only in logs |
| Auditing & logging | `audit.log` + stdout: logins, failures, lockouts, denials, data changes |
