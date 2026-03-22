# Discovery Agent API (DADB)

Flask + PyMongo backend aligned with **DADB** collections: `users`, `departments`, `logs`, `screenshots`.

## Setup

```bash
cd DA_backend-main
python -m venv venv
.\venv\Scripts\activate   # Windows
pip install -r requirements.txt
# includes flask-compress for gzip JSON responses (faster over slow networks)
copy .env.example .env     # edit MONGO_URI / JWT_SECRET
python run.py
```

Server: `http://127.0.0.1:5000` (same as frontend `VITE_API_BASE_URL` default).

## Auth

- Users collection must include **`password_hash`** (bcrypt) for dashboard login (not shown in API responses).
- Login: `POST /api/auth/login` `{ "email", "password" }` → JWT.
- First `POST /api/auth/register` works without token (bootstrap); after that only **C_SUITE** can register new users via API.

## Data rules

- **Logs / screenshots** list endpoints filter by **`user_mac_id`** + date range on **`ts`** (ISO strings, UTC day range from `from`/`to` query params).
- Indexes are created on app startup (`app/db.py` → `ensure_indexes()`).
- RBAC: **C_SUITE** all devices; **DEPARTMENT_HEAD** same `department` field as `users.department`; **DEPARTMENT_MEMBER** only own `user_mac_id`.

## Frontend

Point `DA_Frontend-main/.env` `VITE_API_BASE_URL` to this server.
