# Radhika Sweets — Full-Stack QR Menu, Ordering & Secured API

## Branches Covered
- Maholi Road, Mathura
- Township, Mathura
- Raya, Mathura
- Krishna Nagar, Mathura

## Project Structure
- `frontend/index.html` — Responsive, SEO & Schema.org optimized website with QR Menu (`?branch=`), Customer Rating System below menu, Online Ordering Cart, Branch QR PNG Generator, and Admin Portal.
- `frontend/robots.txt` & `frontend/sitemap.xml` — Search engine indexing files.
- `backend/worker.js` — Secured Cloudflare Worker API (HMAC-SHA256 JWT auth, PBKDF2-SHA256 password verification, parameterized D1 SQL queries, rate limiting, CORS whitelist, security headers).
- `backend/schema.sql` & `backend/wrangler.toml` — Cloudflare D1 SQLite schema and Worker configuration.

## Quick Deploy (Cloudflare Pages + Workers + D1)
1. Create D1 database: `npx wrangler d1 create radhika_sweets_db`
2. Run schema: `npx wrangler d1 execute radhika_sweets_db --file=backend/schema.sql`
3. Set Worker secrets:
   - `npx wrangler secret put JWT_SECRET`
   - `npx wrangler secret put ADMIN_PASSWORD_HASH` (format: `pbkdf2$<saltHex>$<hashHex>`)
4. Deploy Worker: `cd backend && npx wrangler deploy`
5. Set `API_BASE` in `frontend/index.html` to your Worker URL and deploy `frontend/` to Cloudflare Pages.
