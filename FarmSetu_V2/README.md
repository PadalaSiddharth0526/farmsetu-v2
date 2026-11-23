# FarmSetu V2 — isolated rebuild

A React + TypeScript + Vite frontend and FastAPI + SQLAlchemy backend targeting PostgreSQL. **The existing FarmSetu production site is not modified.**

## Local development

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Set DATABASE_URL and JWT_SECRET in your shell (see .env.example)
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Tests:

```bash
cd backend
PYTHONPATH=. pytest -q
```

## PostgreSQL

Create a new, empty PostgreSQL database for V2. Set `DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE`. SQLAlchemy creates `users`, `products`, `orders`, `purchase_groups`, `group_memberships`, and `group_quotes` on startup. For production, use versioned Alembic migrations instead of automatic `create_all`.

## Important setup and security

- Set a **strong unique `JWT_SECRET`** in the backend environment and set `CORS_ORIGINS` to the frontend URL. Configure `VITE_API_URL` to the public HTTPS backend URL.
- Bootstrap an admin **out-of-band** by creating a user with role `admin` using a trusted database administration process. The public registration endpoint intentionally forbids admin signups. Never expose admin credentials or a public admin seed endpoint.
- All farmers and listings require explicit admin approval. **Do not mark unverified produce as verified.**
- This is a pilot/MVP, not a production-hardened platform. Before public launch, add Alembic migrations, PostgreSQL integration tests, rate limiting, email verification, password reset, audit trails, admin MFA, operational monitoring, transactional emails, and security review. Token storage in localStorage should be replaced with hardened session handling before production.
- Payments are cash-on-delivery only. No payment gateway is integrated.
- New database is separate from the current Supabase project. No existing users or orders are migrated automatically.
- The backend can run on Render/Railway/Fly or another Python host; frontend can deploy to a **new Vercel project**. Do not change existing production aliases until V2 is tested.
