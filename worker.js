function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  const len = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;
  for (let i = 0; i < len; i++) {
    diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }
  return diff === 0;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function signJWT(payload, secret) {
  const enc = new TextEncoder();
  const header = base64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = base64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = base64url(await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`)));
  return `${header}.${body}.${sig}`;
}

async function handleAuth(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  if (!body.password || !timingSafeEqual(body.password, env.PASSWORD)) {
    return new Response(JSON.stringify({ ok: false }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const exp = Math.floor(Date.now() / 1000) + 86400 * 90; // 90 days
  const token = await signJWT({ sub: 'user', exp }, env.JWT_SECRET);

  return new Response(JSON.stringify({ ok: true, token }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

async function requireAuth(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  return verifyJWT(token, env.JWT_SECRET);
}

const VALID_PAYERS = ['虎', '梅'];
const KV_KEY = 'expenses';
const JSON_HEADERS = { 'Content-Type': 'application/json' };

async function getExpenses(env) {
  return (await env.EXPENSES_KV.get(KV_KEY, 'json')) ?? [];
}

async function putExpenses(env, list) {
  await env.EXPENSES_KV.put(KV_KEY, JSON.stringify(list));
}

async function handleGetExpenses(env) {
  const list = await getExpenses(env);
  list.sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0));
  return new Response(JSON.stringify({ ok: true, expenses: list }), { headers: JSON_HEADERS });
}

async function handlePostExpense(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid json' }), { status: 400, headers: JSON_HEADERS });
  }

  const item = (body.item ?? '').trim();
  const amount = parseInt(body.amount, 10);
  const paidBy = body.paidBy;

  if (!item || !Number.isFinite(amount) || amount <= 0 || !VALID_PAYERS.includes(paidBy)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid' }), { status: 400, headers: JSON_HEADERS });
  }

  const list = await getExpenses(env);
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const createdAt = new Date().toISOString();
  const sort = list.length > 0 ? Math.max(...list.map(e => e.sort ?? 0)) + 1 : 0;
  const expense = { id, item, amount, paidBy, createdAt, sort };

  list.push(expense);
  await putExpenses(env, list);

  return new Response(JSON.stringify({ ok: true, expense }), { status: 201, headers: JSON_HEADERS });
}

async function handleDeleteExpense(id, env) {
  const list = await getExpenses(env);
  const next = list.filter(e => e.id !== id);
  if (next.length === list.length) {
    return new Response(JSON.stringify({ ok: false }), { status: 404, headers: JSON_HEADERS });
  }
  await putExpenses(env, next);
  return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
}

async function handlePatchExpense(id, request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid json' }), { status: 400, headers: JSON_HEADERS });
  }
  const list = await getExpenses(env);
  const idx = list.findIndex(e => e.id === id);
  if (idx === -1) {
    return new Response(JSON.stringify({ ok: false }), { status: 404, headers: JSON_HEADERS });
  }
  list[idx] = { ...list[idx], settled: !!body.settled };
  await putExpenses(env, list);
  return new Response(JSON.stringify({ ok: true, expense: list[idx] }), { headers: JSON_HEADERS });
}

async function handleReorderExpenses(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: JSON_HEADERS });
  }
  if (!Array.isArray(body.ids)) {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: JSON_HEADERS });
  }
  const list = await getExpenses(env);
  body.ids.forEach((id, i) => {
    const item = list.find(e => e.id === id);
    if (item) item.sort = i;
  });
  await putExpenses(env, list);
  return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
}

async function handleExpenses(request, env, url) {
  const payload = await requireAuth(request, env);
  if (!payload) return new Response(JSON.stringify({ ok: false }), { status: 401, headers: JSON_HEADERS });

  if (request.method === 'GET') return handleGetExpenses(env);
  if (request.method === 'POST') return handlePostExpense(request, env);
  if (request.method === 'PUT' && url.pathname === '/expenses/reorder') {
    return handleReorderExpenses(request, env);
  }
  if (request.method === 'DELETE') {
    const id = url.pathname.replace('/expenses/', '');
    return handleDeleteExpense(id, env);
  }
  if (request.method === 'PATCH') {
    const id = url.pathname.replace('/expenses/', '');
    return handlePatchExpense(id, request, env);
  }
  return new Response(JSON.stringify({ ok: false }), { status: 405, headers: JSON_HEADERS });
}

// SOUVENIRS
const SOUVENIRS_KEY = 'souvenirs';
const VALID_OWNERS = ['虎', '梅'];

async function getSouvenirs(env) {
  return (await env.EXPENSES_KV.get(SOUVENIRS_KEY, 'json')) ?? [];
}

async function putSouvenirs(env, list) {
  await env.EXPENSES_KV.put(SOUVENIRS_KEY, JSON.stringify(list));
}

async function handleGetSouvenirs(env) {
  const list = await getSouvenirs(env);
  list.sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0));
  return new Response(JSON.stringify({ ok: true, souvenirs: list }), { headers: JSON_HEADERS });
}

async function handlePostSouvenir(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid json' }), { status: 400, headers: JSON_HEADERS });
  }

  const text = (body.text ?? '').trim();
  const owner = body.owner;

  if (!text || !VALID_OWNERS.includes(owner)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid' }), { status: 400, headers: JSON_HEADERS });
  }

  const list = await getSouvenirs(env);
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const createdAt = new Date().toISOString();
  const sameOwner = list.filter(s => s.owner === owner);
  const sort = sameOwner.length > 0 ? Math.max(...sameOwner.map(s => s.sort ?? 0)) + 1 : 0;
  const item = { id, text, owner, checked: false, createdAt, sort };

  list.push(item);
  await putSouvenirs(env, list);

  return new Response(JSON.stringify({ ok: true, souvenir: item }), { status: 201, headers: JSON_HEADERS });
}

async function handleDeleteSouvenir(id, env) {
  const list = await getSouvenirs(env);
  const next = list.filter(s => s.id !== id);
  if (next.length === list.length) {
    return new Response(JSON.stringify({ ok: false }), { status: 404, headers: JSON_HEADERS });
  }
  await putSouvenirs(env, next);
  return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
}

async function handlePatchSouvenir(id, request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid json' }), { status: 400, headers: JSON_HEADERS });
  }
  const list = await getSouvenirs(env);
  const idx = list.findIndex(s => s.id === id);
  if (idx === -1) {
    return new Response(JSON.stringify({ ok: false }), { status: 404, headers: JSON_HEADERS });
  }
  list[idx] = { ...list[idx], checked: !!body.checked };
  await putSouvenirs(env, list);
  return new Response(JSON.stringify({ ok: true, souvenir: list[idx] }), { headers: JSON_HEADERS });
}

async function handleReorderSouvenirs(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: JSON_HEADERS });
  }
  if (!Array.isArray(body.ids)) {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: JSON_HEADERS });
  }
  const list = await getSouvenirs(env);
  body.ids.forEach((id, i) => {
    const item = list.find(s => s.id === id);
    if (item) item.sort = i;
  });
  await putSouvenirs(env, list);
  return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
}

async function handleSouvenirs(request, env, url) {
  const payload = await requireAuth(request, env);
  if (!payload) return new Response(JSON.stringify({ ok: false }), { status: 401, headers: JSON_HEADERS });

  if (request.method === 'GET') return handleGetSouvenirs(env);
  if (request.method === 'POST') return handlePostSouvenir(request, env);
  if (request.method === 'PUT' && url.pathname === '/souvenirs/reorder') {
    return handleReorderSouvenirs(request, env);
  }
  if (request.method === 'DELETE') {
    const id = url.pathname.replace('/souvenirs/', '');
    return handleDeleteSouvenir(id, env);
  }
  if (request.method === 'PATCH') {
    const id = url.pathname.replace('/souvenirs/', '');
    return handlePatchSouvenir(id, request, env);
  }
  return new Response(JSON.stringify({ ok: false }), { status: 405, headers: JSON_HEADERS });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/auth') {
      return handleAuth(request, env);
    }

    if (url.pathname === '/expenses' || url.pathname.startsWith('/expenses/')) {
      return handleExpenses(request, env, url);
    }

    if (url.pathname === '/souvenirs' || url.pathname.startsWith('/souvenirs/')) {
      return handleSouvenirs(request, env, url);
    }

    if (url.pathname.startsWith('/files/')) {
      const token = request.headers.get('Authorization')?.replace('Bearer ', '')
        ?? url.searchParams.get('token');
      const payload = token ? await verifyJWT(token, env.JWT_SECRET) : null;
      if (!payload) return new Response('Unauthorized', { status: 401 });
    }

    return env.ASSETS.fetch(request);
  },
};
