const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-User-Id',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function handleAPI(request, env, url) {
  const method = request.method;
  const path = url.pathname.replace('/api', '');
  const userId = request.headers.get('X-User-Id');

  if (method === 'OPTIONS') return new Response(null, { headers: CORS });

  // Check username availability
  if (path === '/users/check' && method === 'GET') {
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
    const display_name = (body.display_name || '').trim();
    if (!username || !display_name) return err('username and display_name required');
    if (!/^[a-z0-9_]{3,30}$/.test(username)) return err('Invalid username');
    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (existing) return err('Username taken', 409);
    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO users (id, username, display_name, whatsapp) VALUES (?, ?, ?, ?)'
    ).bind(id, username, display_name, body.whatsapp || '').run();
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
    return json({ user });
  }

  if (!userId) return err('Unauthorized', 401);

  // Get current user
  if (path === '/me' && method === 'GET') {
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    if (!user) return err('Not found', 404);
    return json({ user });
  }

  // Update profile
  if (path === '/me/profile' && method === 'PUT') {
    const b = await request.json();
    await env.DB.prepare(
      'UPDATE users SET display_name = ?, bio = ?, avatar_url = ?, username = ? WHERE id = ?'
    ).bind(b.display_name || '', b.bio || '', b.avatar_url || '', (b.username || '').toLowerCase(), userId).run();
    return json({ ok: true });
  }

  // Update settings
  if (path === '/me/settings' && method === 'PUT') {
    const b = await request.json();
    await env.DB.prepare(
      'UPDATE users SET whatsapp = ?, currency = ?, grid_cols = ?, show_unavailable = ?, social_bento = ? WHERE id = ?'
    ).bind(b.whatsapp || '', b.currency || 'USD', b.grid_cols || 2, b.show_unavailable ? 1 : 0, b.social_bento ? 1 : 0, userId).run();
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
      const b = await request.json();
      if (!b.name) return err('name required');
      const result = await env.DB.prepare(
        'INSERT INTO products (user_id, name, price, category, description, stock, available, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(userId, b.name, b.price || 0, b.category || 'Other', b.description || '', b.stock || 0, b.available !== false ? 1 : 0, b.image_url || '').run();
      const product = await env.DB.prepare('SELECT * FROM products WHERE rowid = ?').bind(result.meta.last_row_id).first();
      return json({ product });
    }
  }

  const pm = path.match(/^\/products\/(\d+)$/);
  if (pm) {
    const pid = parseInt(pm[1]);
    if (method === 'PUT') {
      const b = await request.json();
      await env.DB.prepare(
        'UPDATE products SET name = ?, price = ?, category = ?, description = ?, stock = ?, available = ?, image_url = ? WHERE id = ? AND user_id = ?'
      ).bind(b.name, b.price || 0, b.category || 'Other', b.description || '', b.stock || 0, b.available !== false ? 1 : 0, b.image_url || '', pid, userId).run();
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
      await env.DB.prepare(
        'INSERT INTO orders (id, user_id, customer_name, customer_phone, items, total, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(id, userId, b.customer_name || 'Customer', b.customer_phone || '', JSON.stringify(b.items || []), b.total || 0, 'pending').run();
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(id).first();
      return json({ order: { ...order, items: JSON.parse(order.items) } });
    }
  }

  const om = path.match(/^\/orders\/([^/]+)$/);
  if (om && method === 'PUT') {
    const b = await request.json();
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
      const b = await request.json();
      await env.DB.prepare('DELETE FROM links WHERE user_id = ?').bind(userId).run();
      const items = b.links || [];
      for (let i = 0; i < items.length; i++) {
        await env.DB.prepare(
          'INSERT INTO links (user_id, platform, url, sort_order) VALUES (?, ?, ?, ?)'
        ).bind(userId, items[i].platform, items[i].url, i).run();
      }
      return json({ ok: true });
    }
  }

  return err('Not found', 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleAPI(request, env, url);
    return env.ASSETS.fetch(request);
  },
};
