# LUXE DRON License API

Backend starter for license activation, session heartbeats and opt-in diagnostic/command event logs.

## Deploy

1. Create a PostgreSQL database (for example, a free-tier Neon project) and copy its connection string.
2. Push these files to a private GitHub repository.
3. In Render, create a **Blueprint** from that repository. Render reads `render.yaml`.
4. Set `DATABASE_URL` to the PostgreSQL connection string. Keep `ADMIN_API_KEY` secret; Render generates it if the Blueprint supports generated values.
5. Deploy. Check `/health`.

## API

- `POST /api/activate`
- `POST /api/heartbeat`
- `POST /api/events`
- `POST /admin/licenses` (header `X-Admin-Key`)
- `POST /admin/licenses/{license_key}/revoke` (header `X-Admin-Key`)
- `GET /admin/sessions` (header `X-Admin-Key`)
- `GET /admin/events` (header `X-Admin-Key`)

License keys are stored as SHA-256 hashes. Minecraft session tokens, passwords and IP addresses are not collected. Common authentication commands (`/login`, `/register`, etc.) have their arguments redacted automatically. Tell users clearly what command/event telemetry is collected and obtain appropriate consent before enabling it.

This is a backend scaffold, not yet wired into the Minecraft mod. The client integration and admin web UI are separate steps. Do not publish the admin key or database connection string.
