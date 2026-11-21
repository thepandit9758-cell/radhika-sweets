/**
 * Radhika Sweets — Fully Secured Cloudflare Worker API
 * Security: HMAC-SHA256 JWT, PBKDF2-SHA256 Password Verification,
 * Parameterized D1 SQL, CORS Whitelist, Rate Limiting, Security Headers.
 */

const VALID_BRANCHES = ['Maholi Road', 'Township, Mathura', 'Raya', 'Krishna Nagar'];
const rateLimitMap = new Map();

function securityHeaders(origin, allowedOrigin) {
  const corsOrigin = origin === allowedOrigin ? origin : allowedOrigin;
  return {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers });
}

function checkRateLimit(ip, limit = 30, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + windowMs;
  }
  entry.count += 1;
  rateLimitMap.set(ip, entry);
  return entry.count <= limit;
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJWT(payload, secret) {
  const enc = new TextEncoder();
  const header = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${parts[0]}.${parts[1]}`));
    if (!ok) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

async function verifyPBKDF2(password, storedHash) {
  // storedHash format: pbkdf2$saltHex$hashHex
  const [algo, saltHex, expectedHex] = (storedHash || '').split('$');
  if (algo !== 'pbkdf2' || !saltHex || !expectedHex) return false;
  const enc = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
  const actualHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  return actualHex === expectedHex;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const headers = securityHeaders(origin, env.ALLOWED_ORIGIN || '*');
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if (!checkRateLimit(ip, 60, 60000)) {
      return json({ error: 'Too many requests. Please slow down.' }, 429, headers);
    }

    // 1. Public: Get Menu
    if (url.pathname === '/api/menu' && request.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM menu_items ORDER BY id DESC').all();
      return json({ items: results }, 200, headers);
    }

    // 2. Public: Get Reviews
    if (url.pathname === '/api/reviews' && request.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM reviews ORDER BY id DESC LIMIT 50').all();
      return json({ reviews: results }, 200, headers);
    }

    // 3. Public: Submit Rating / Review
    if (url.pathname === '/api/reviews' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      if (!body || !body.customer_name || !VALID_BRANCHES.includes(body.branch) || !(body.stars >= 1 && body.stars <= 5) || !body.comment) {
        return json({ error: 'Invalid review payload' }, 400, headers);
      }
      await env.DB.prepare('INSERT INTO reviews (customer_name, branch, stars, comment) VALUES (?, ?, ?, ?)')
        .bind(body.customer_name.slice(0, 60), body.branch, Number(body.stars), body.comment.slice(0, 400)).run();
      return json({ ok: true }, 201, headers);
    }

    // 4. Public: Place Customer Order
    if (url.pathname === '/api/orders' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      if (!body || !VALID_BRANCHES.includes(body.branch) || !/^[0-9]{10}$/.test(body.phone || '') || !Array.isArray(body.items) || !body.items.length) {
        return json({ error: 'Invalid order details' }, 400, headers);
      }
      const orderId = 'RS-' + Math.floor(1000 + Math.random() * 9000);
      await env.DB.prepare(
        'INSERT INTO orders (id, branch, order_type, customer_name, phone, address, items_json, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        orderId, body.branch, body.order_type || 'Dine-In',
        String(body.customer_name).slice(0, 80), body.phone,
        String(body.address || '').slice(0, 200),
        JSON.stringify(body.items), Number(body.total_amount || 0)
      ).run();
      return json({ ok: true, orderId }, 201, headers);
    }

    // 5. Admin Auth: Login
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      if (!checkRateLimit(`login:${ip}`, 5, 60000)) {
        return json({ error: 'Too many login attempts. Try again in 1 minute.' }, 429, headers);
      }
      const body = await request.json().catch(() => null);
      const validUser = body?.username === (env.ADMIN_USERNAME || 'admin');
      const validPass = await verifyPBKDF2(body?.password || '', env.ADMIN_PASSWORD_HASH);
      if (!validUser || !validPass) {
        return json({ error: 'Invalid credentials' }, 401, headers);
      }
      const token = await signJWT({ sub: body.username, role: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 }, env.JWT_SECRET);
      return json({ token }, 200, headers);
    }

    // Protected Admin Routes
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const user = token ? await verifyJWT(token, env.JWT_SECRET) : null;
    if (!user || user.role !== 'admin') {
      return json({ error: 'Unauthorized' }, 401, headers);
    }

    // 6. Admin: Add Menu Item
    if (url.pathname === '/api/menu' && request.method === 'POST') {
      const b = await request.json().catch(() => null);
      if (!b || !b.name || !b.category || !(Number(b.price) > 0) || !b.unit) {
        return json({ error: 'Missing required menu fields' }, 400, headers);
      }
      await env.DB.prepare(
        'INSERT INTO menu_items (name, category, price, unit, img_key, description, badge, available) VALUES (?, ?, ?, ?, ?, ?, ?, 1)'
      ).bind(b.name.slice(0, 80), b.category, Number(b.price), b.unit.slice(0, 30), b.img_key || 'royal', (b.description || '').slice(0, 250), b.badge || 'New Arrival').run();
      return json({ ok: true }, 201, headers);
    }

    // 7. Admin: Toggle Stock / Delete Menu Item
    if (url.pathname.startsWith('/api/menu/') && request.method === 'PATCH') {
      const id = Number(url.pathname.split('/').pop());
      const b = await request.json().catch(() => ({}));
      await env.DB.prepare('UPDATE menu_items SET available = ? WHERE id = ?').bind(b.available ? 1 : 0, id).run();
      return json({ ok: true }, 200, headers);
    }

    if (url.pathname.startsWith('/api/menu/') && request.method === 'DELETE') {
      const id = Number(url.pathname.split('/').pop());
      await env.DB.prepare('DELETE FROM menu_items WHERE id = ?').bind(id).run();
      return json({ ok: true }, 200, headers);
    }

    // 8. Admin: View & Update Orders
    if (url.pathname === '/api/orders' && request.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 100').all();
      return json({ orders: results }, 200, headers);
    }

    if (url.pathname.startsWith('/api/orders/') && request.method === 'PATCH') {
      const id = url.pathname.split('/').pop();
      const b = await request.json().catch(() => ({}));
      if (!['Pending', 'Preparing', 'Ready', 'Completed'].includes(b.status)) {
        return json({ error: 'Invalid status' }, 400, headers);
      }
      await env.DB.prepare('UPDATE orders SET status = ? WHERE id = ?').bind(b.status, id).run();
      return json({ ok: true }, 200, headers);
    }

    return json({ error: 'Not found' }, 404, headers);
  }
};
