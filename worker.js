const CORS = {
  'Access-Control-Allow-Origin': 'https://lifaaq.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Session-Id',
  'Vary': 'Origin',
};

async function verifyTurnstile(token, secret, ip) {
  const fd = new FormData();
  fd.append('secret', secret);
  fd.append('response', token);
  if (ip) fd.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', body: fd,
  });
  const data = await res.json();
  return data.success === true;
}

const SOMALI_PREFIXES = ['61','77','63','90','70','62','65','66'];
function isValidWhatsapp(wa) {
  if (!wa) return true;
  if (!/^\+\d{7,15}$/.test(wa)) return false;
  if (wa.startsWith('+252')) {
    const local = wa.slice(4);
    return local.length === 9 && SOMALI_PREFIXES.some(p => local.startsWith(p));
  }
  return true;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function createSession(userId, env) {
  const sid = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO sessions (id, user_id) VALUES (?, ?)').bind(sid, userId).run();
  return sid;
}

const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

async function resolveSession(sid, env) {
  if (!sid) return null;
  const row = await env.DB.prepare(
    'SELECT user_id, created_at FROM sessions WHERE id = ?'
  ).bind(sid).first();
  if (!row) return null;
  if (row.created_at && Date.now() - new Date(row.created_at).getTime() > SESSION_TTL_MS) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
    return null;
  }
  return row.user_id;
}

async function checkRateLimit(key, max, windowSecs, env) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % windowSecs);
  const row = await env.DB.prepare(
    'SELECT count, window_start FROM rate_limits WHERE key = ?'
  ).bind(key).first();
  if (!row || row.window_start < windowStart) {
    await env.DB.prepare(
      'INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)'
    ).bind(key, windowStart).run();
    return false;
  }
  if (row.count >= max) return true;
  await env.DB.prepare(
    'UPDATE rate_limits SET count = count + 1 WHERE key = ?'
  ).bind(key).run();
  return false;
}

const VALID_CURRENCIES = ['USD','EUR','GBP','NGN','KES','GHS','SOS'];
const VALID_STATUSES   = ['pending','confirmed','delivered','cancelled'];

async function handleAPI(request, env, url) {
  const method = request.method;
  const path = url.pathname.replace('/api', '');
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (method === 'OPTIONS') return new Response(null, { headers: CORS });

  // Check username availability
  if (path === '/users/check' && method === 'GET') {
    if (await checkRateLimit(`check:${ip}`, 30, 60, env)) return err('Too many requests', 429);
    const username = (url.searchParams.get('username') || '').toLowerCase().trim();
    if (!username) return err('username required');
    if (!/^[a-z0-9_]{3,30}$/.test(username)) return json({ available: false, reason: 'invalid' });
    const row = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    return json({ available: !row });
  }

  // Create user
  if (path === '/users' && method === 'POST') {
    const body = await request.json();
    const username = (body.username || '').toLowerCase().trim();
    const display_name = (body.display_name || '').trim().slice(0, 100);
    if (!username || !display_name) return err('username and display_name required');
    if (!/^[a-z0-9_]{3,30}$/.test(username)) return err('Invalid username');
    const turnstileOk = await verifyTurnstile(body.turnstile_token || '', env.TURNSTILE_SECRET, ip);
    if (!turnstileOk) return err('Bot check failed. Please try again.', 403);
    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (existing) return err('Username taken', 409);
    const waRaw = (body.whatsapp || '').trim();
    if (!isValidWhatsapp(waRaw)) return err('Invalid WhatsApp number format', 400);
    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO users (id, username, display_name, whatsapp) VALUES (?, ?, ?, ?)'
    ).bind(id, username, display_name, waRaw).run();
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
    const session_id = await createSession(id, env);
    return json({ user, session_id });
  }

  // Login with username + WhatsApp number
  if (path === '/sessions/login' && method === 'POST') {
    if (await checkRateLimit(`login:${ip}`, 10, 60, env)) return err('Too many requests', 429);
    const body = await request.json();
    const username = (body.username || '').toLowerCase().trim();
    const whatsapp = (body.whatsapp || '').trim();
    if (!username || !whatsapp) return err('username and WhatsApp number required');
    const turnstileOk = await verifyTurnstile(body.turnstile_token || '', env.TURNSTILE_SECRET, ip);
    if (!turnstileOk) return err('Bot check failed. Please try again.', 403);
    const user = await env.DB.prepare('SELECT id, whatsapp FROM users WHERE username = ?').bind(username).first();
    if (!user || !user.whatsapp) return err('Invalid username or phone number', 401);
    const norm = (p) => p.replace(/[\s\-().]/g, '');
    if (norm(user.whatsapp) !== norm(whatsapp)) return err('Invalid username or phone number', 401);
    const session_id = await createSession(user.id, env);
    return json({ session_id });
  }

  // One-time migration: exchange a legacy user_id UUID for a proper session token
  if (path === '/sessions' && method === 'POST') {
    if (await checkRateLimit(`sessions:${ip}`, 10, 60, env)) return err('Too many requests', 429);
    const body = await request.json();
    const legacyUserId = (body.user_id || '').trim();
    if (!legacyUserId) return err('user_id required');
    const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(legacyUserId).first();
    if (!user) return err('Not found', 404);
    const session_id = await createSession(legacyUserId, env);
    return json({ session_id });
  }

  // Logout — delete current session
  if (path === '/sessions/me' && method === 'DELETE') {
    const sid = request.headers.get('X-Session-Id');
    if (sid) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
    return json({ ok: true });
  }

  // Public store — no auth required
  const storePath = path.match(/^\/store\/([a-z0-9_]+)$/i);
  if (storePath && method === 'GET') {
    if (await checkRateLimit(`store:${ip}`, 60, 60, env)) return err('Too many requests', 429);
    const username = storePath[1].toLowerCase();
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) return err('Store not found', 404);
    const productsQuery = user.show_unavailable
      ? 'SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC'
      : 'SELECT * FROM products WHERE user_id = ? AND available = 1 ORDER BY created_at DESC';
    const { results: products } = await env.DB.prepare(productsQuery).bind(user.id).all();
    const { results: links } = await env.DB.prepare('SELECT * FROM links WHERE user_id = ? ORDER BY sort_order').bind(user.id).all();
    return json({
      user: {
        username: user.username, display_name: user.display_name, bio: user.bio,
        avatar_url: user.avatar_url, whatsapp: user.whatsapp, currency: user.currency,
        grid_cols: user.grid_cols, show_unavailable: user.show_unavailable, social_bento: user.social_bento,
      },
      products,
      links,
    });
  }

  // All routes below require a valid session
  const sid = request.headers.get('X-Session-Id');
  const userId = await resolveSession(sid, env);
  if (!userId) return err('Unauthorized', 401);

  // Get current user
  if (path === '/me' && method === 'GET') {
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    if (!user) return err('Not found', 404);
    return json({ user });
  }

  // Update profile
  if (path === '/me/profile' && method === 'PUT') {
    if (await checkRateLimit(`profile:${userId}`, 10, 60, env)) return err('Too many requests', 429);
    const b = await request.json();
    const newUsername = (b.username || '').toLowerCase().trim();
    const displayName = (b.display_name || '').trim().slice(0, 100);
    const bio = (b.bio || '').slice(0, 150);
    const avatarUrl = (b.avatar_url || '').slice(0, 800000); // base64 images can be large
    if (!displayName) return err('Display name required');
    if (newUsername && !/^[a-z0-9_]{3,30}$/.test(newUsername)) return err('Invalid username');
    if (newUsername) {
      const taken = await env.DB.prepare(
        'SELECT id FROM users WHERE username = ? AND id != ?'
      ).bind(newUsername, userId).first();
      if (taken) return err('Username already taken', 409);
    }
    await env.DB.prepare(
      'UPDATE users SET display_name = ?, bio = ?, avatar_url = ?, username = ? WHERE id = ?'
    ).bind(displayName, bio, avatarUrl, newUsername, userId).run();
    return json({ ok: true });
  }

  // Update settings
  if (path === '/me/settings' && method === 'PUT') {
    if (await checkRateLimit(`settings:${userId}`, 10, 60, env)) return err('Too many requests', 429);
    const b = await request.json();
    const waRaw = (b.whatsapp || '').trim();
    if (!isValidWhatsapp(waRaw)) return err('Invalid WhatsApp number format', 400);
    const currency = VALID_CURRENCIES.includes(b.currency) ? b.currency : 'USD';
    const gridCols = [2, 3, 4].includes(b.grid_cols) ? b.grid_cols : 2;
    await env.DB.prepare(
      'UPDATE users SET whatsapp = ?, currency = ?, grid_cols = ?, show_unavailable = ?, social_bento = ? WHERE id = ?'
    ).bind(waRaw, currency, gridCols, b.show_unavailable ? 1 : 0, b.social_bento ? 1 : 0, userId).run();
    return json({ ok: true });
  }

  // Dismiss links onboarding banner
  if (path === '/me/onboarding' && method === 'PUT') {
    await env.DB.prepare('UPDATE users SET onboarding_done = 1 WHERE id = ?').bind(userId).run();
    return json({ ok: true });
  }

  // Products
  if (path === '/products') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC'
      ).bind(userId).all();
      return json({ products: results });
    }
    if (method === 'POST') {
      if (await checkRateLimit(`products:${userId}`, 30, 60, env)) return err('Too many requests', 429);
      const b = await request.json();
      const name = (b.name || '').trim().slice(0, 200);
      if (!name) return err('name required');
      const price = Math.max(0, parseFloat(b.price) || 0);
      const stock = Math.max(0, parseInt(b.stock) || 0);
      const category = (b.category || 'Other').slice(0, 50);
      const description = (b.description || '').slice(0, 1000);
      const imageUrl = (b.image_url || '').slice(0, 800000);
      const result = await env.DB.prepare(
        'INSERT INTO products (user_id, name, price, category, description, stock, available, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(userId, name, price, category, description, stock, b.available !== false ? 1 : 0, imageUrl).run();
      const product = await env.DB.prepare('SELECT * FROM products WHERE rowid = ?').bind(result.meta.last_row_id).first();
      return json({ product });
    }
  }

  const pm = path.match(/^\/products\/(\d+)$/);
  if (pm) {
    const pid = parseInt(pm[1]);
    if (method === 'PUT') {
      const b = await request.json();
      const name = (b.name || '').trim().slice(0, 200);
      if (!name) return err('name required');
      const price = Math.max(0, parseFloat(b.price) || 0);
      const stock = Math.max(0, parseInt(b.stock) || 0);
      const category = (b.category || 'Other').slice(0, 50);
      const description = (b.description || '').slice(0, 1000);
      const imageUrl = (b.image_url || '').slice(0, 800000);
      await env.DB.prepare(
        'UPDATE products SET name = ?, price = ?, category = ?, description = ?, stock = ?, available = ?, image_url = ? WHERE id = ? AND user_id = ?'
      ).bind(name, price, category, description, stock, b.available !== false ? 1 : 0, imageUrl, pid, userId).run();
      const product = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND user_id = ?').bind(pid, userId).first();
      return json({ product });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM products WHERE id = ? AND user_id = ?').bind(pid, userId).run();
      return json({ ok: true });
    }
  }

  // Orders
  if (path === '/orders') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC'
      ).bind(userId).all();
      return json({ orders: results.map(o => ({ ...o, items: JSON.parse(o.items || '[]') })) });
    }
    if (method === 'POST') {
      const b = await request.json();
      const id = 'ORD-' + Date.now();
      const customerName = (b.customer_name || 'Customer').slice(0, 100);
      const customerPhone = (b.customer_phone || '').slice(0, 30);
      const total = Math.max(0, parseFloat(b.total) || 0);
      const items = JSON.stringify((b.items || []).slice(0, 100));
      await env.DB.prepare(
        'INSERT INTO orders (id, user_id, customer_name, customer_phone, items, total, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(id, userId, customerName, customerPhone, items, total, 'pending').run();
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(id).first();
      return json({ order: { ...order, items: JSON.parse(order.items) } });
    }
  }

  const om = path.match(/^\/orders\/([^/]+)$/);
  if (om && method === 'PUT') {
    if (await checkRateLimit(`orders:${userId}`, 60, 60, env)) return err('Too many requests', 429);
    const b = await request.json();
    if (!VALID_STATUSES.includes(b.status)) return err('Invalid status');
    await env.DB.prepare('UPDATE orders SET status = ? WHERE id = ? AND user_id = ?').bind(b.status, om[1], userId).run();
    return json({ ok: true });
  }

  // Links
  if (path === '/links') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM links WHERE user_id = ? ORDER BY sort_order'
      ).bind(userId).all();
      return json({ links: results });
    }
    if (method === 'PUT') {
      if (await checkRateLimit(`links:${userId}`, 20, 60, env)) return err('Too many requests', 429);
      const b = await request.json();
      const items = (b.links || []).slice(0, 20);
      const statements = [env.DB.prepare('DELETE FROM links WHERE user_id = ?').bind(userId)];
      for (let i = 0; i < items.length; i++) {
        const rawUrl = (items[i].url || '').trim().slice(0, 500);
        if (!/^https?:\/\//i.test(rawUrl)) continue;
        const platform = (items[i].platform || 'other').slice(0, 30);
        const title = (items[i].title || '').trim().slice(0, 100);
        const highlight = items[i].highlight ? 1 : 0;
        const linkImageUrl = (items[i].image_url || '').slice(0, 800000);
        statements.push(
          env.DB.prepare('INSERT INTO links (user_id, platform, url, title, highlight, image_url, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(userId, platform, rawUrl, title, highlight, linkImageUrl, i)
        );
      }
      await env.DB.batch(statements);
      return json({ ok: true });
    }
  }

  return err('Not found', 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleAPI(request, env, url);
    // Serve index.html for public store routes (/@username or /username)
    if (/^\/?@?[a-z0-9_]{3,30}$/i.test(url.pathname) && !url.pathname.includes('.')) {
      return env.ASSETS.fetch(new Request(new URL('/', url).toString(), request));
    }
    return env.ASSETS.fetch(request);
  },
};
