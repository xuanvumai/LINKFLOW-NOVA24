# LINKFLOW NOVA24

Node.js + Express + PostgreSQL application with user accounts, wallet top-ups, a separate admin page, SePay webhook crediting, and a conservative public-link redirect inspector.

## Requirements
- Node.js 20+
- PostgreSQL 14+
- A SePay account/webhook configured to send incoming transfer events

## Run locally
1. Create a PostgreSQL database named `linkflow_nova24`.
2. Copy `.env.example` to `.env` and fill every value. Set a long random `JWT_SECRET`, your MB Bank account details, and the SePay webhook API key.
3. Install and start:

   ```bash
   npm install
   npm start
   ```
4. Open `http://localhost:3000`. Admin: `http://localhost:3000/admin`.
5. On first startup the app creates the admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` if that email does not already exist. Change the password immediately after first login; do not leave the example credentials in production.

## SePay setup
- In SePay, configure the webhook URL as `https://YOUR-DOMAIN/api/webhooks/sepay`.
- Configure the same API key in SePay and `SEPAY_API_KEY`.
- This endpoint accepts the common SePay webhook fields `id`, `transferType`, `transferAmount`, and `content` (also accepts common aliases).
- The payment description must contain the exact generated reference, e.g. `NOVA...`.
- Test with a small transfer first. Confirm the exact authorization header and payload format shown in your SePay dashboard before going live.
- The QR image uses VietQR's public image endpoint. Verify your bank code/account name and scan the generated QR with your banking app before production use.

## Link inspector scope and safety
- Supports HTTP 301/302/303/307/308 redirects and common HTML meta-refresh redirects.
- Checks each destination hostname against private/local IP ranges, limits redirect depth, applies a timeout, and rate-limits requests.
- It does **not** defeat CAPTCHA, login, paywalls, anti-bot protections, browser fingerprinting, or JavaScript challenges. A JavaScript-only redirect may not be resolved by the server-side inspector.
- URL fetching is a security-sensitive feature. For production, additionally enforce outbound network egress rules at the VPS/container firewall (deny loopback, RFC1918, link-local, IPv6 ULA, cloud metadata endpoints and internal DNS), keep Node and dependencies patched, and consider a dedicated isolated resolver service. DNS preflight checks alone are not a complete SSRF defense against DNS rebinding.

## Production checklist
- Serve only over HTTPS; set `BASE_URL` to the public HTTPS origin.
- Use a managed PostgreSQL database, backups, least-privilege DB credentials, and network restrictions.
- Set `NODE_ENV=production`, a unique 32+ character JWT secret, and strong admin credentials.
- Keep `.env` out of Git. Never publish SePay keys or database credentials.
- Add monitoring, audit logging, abuse controls, and a verified payment reconciliation process.
- The app intentionally does not let users spend wallet balance yet; add a transactionally safe order/debit flow before selling services.

## Main routes
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/me`
- `POST /api/resolve` (authenticated)
- `POST /api/topups`, `GET /api/topups`, `GET /api/ledger` (authenticated)
- `POST /api/webhooks/sepay` (SePay API key)
- `GET /admin` (admin UI)
- `GET /api/admin/overview`, `/api/admin/users`, `/api/admin/topups`
- `POST /api/admin/users/:id/adjust` (admin only)

## Notes
The app creates tables automatically from `schema.sql` at startup. For a production deployment, use database migrations rather than relying on startup schema execution.
