/**
 * ВОЛНА — Cloudflare Worker (ПОЛНАЯ ВЕРСИЯ ДЛЯ R2)
 * * Настройки в Dashboard:
 * 1. Variables: SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET, R2_PUBLIC_URL
 * 2. Bindings: R2 Bucket -> Variable name: MEDIA, Bucket: volna-media
 */

// ── СИСТЕМНЫЕ ФУНКЦИИ (JWT, HASH, CORS) ──────────────────────────

async function jwtSign(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const body = btoa(JSON.stringify(payload)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const data = header + '.' + body;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return data + '.' + sigB64;
}

async function jwtVerify(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data = header + '.' + body;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data));
    if (!valid) return null;
    return JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
  } catch { return null; }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2,'0')).join('');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
  return 'pbkdf2:' + saltHex + ':' + hash;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('pbkdf2:')) return false;
  const [, saltHex, storedHash] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hash === storedHash;
}

// ── УТИЛИТЫ ──────────────────────────────────────────────────

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
const err = (msg, status = 400) => json({ error: msg }, status);

function formatTime(isoStr) {
  const d = new Date(isoStr), now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60) return 'только что';
  if (diff < 3600) return Math.floor(diff/60) + 'м назад';
  if (diff < 86400) return Math.floor(diff/3600) + 'ч назад';
  return d.toLocaleDateString('ru');
}

// ── ЗАГРУЗКА В R2 ───────────────────────────────────────────

async function uploadToR2(env, base64, filename) {
  try {
    const parts = base64.split(';base64,');
    const contentType = parts[0].split(':')[1] || 'application/octet-stream';
    const raw = atob(parts[1]);
    const buffer = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buffer[i] = raw.charCodeAt(i);

    // env.MEDIA — это привязка вашего бакета volna-media
    await env.MEDIA.put(filename, buffer, { httpMetadata: { contentType } });
    
    const baseUrl = env.R2_PUBLIC_URL.replace(/\/$/, '');
    return `${baseUrl}/${filename}`;
  } catch (e) {
    console.error('R2 Error:', e);
    return null;
  }
}

// ── SUPABASE CLIENT ──────────────────────────────────────────

function sb(env) {
  const h = { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json', 'Prefer': 'return=representation' };
  return {
    async get(t, q = '') { return fetch(`${env.SUPABASE_URL}/rest/v1/${t}?${q}`, { headers: h }).then(r => r.json()); },
    async post(t, d) { return fetch(`${env.SUPABASE_URL}/rest/v1/${t}`, { method: 'POST', headers: h, body: JSON.stringify(d) }).then(r => r.json()); },
    async patch(t, d, f) { return fetch(`${env.SUPABASE_URL}/rest/v1/${t}?${f}`, { method: 'PATCH', headers: h, body: JSON.stringify(d) }).then(r => r.json()); }
  };
}

// ── ГЛАВНЫЙ ОБРАБОТЧИК ────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

    const supabase = sb(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '');
    const method = request.method;
    const query = Object.fromEntries(url.searchParams);

    let body = {};
    if (['POST','PATCH','PUT'].includes(method)) { try { body = await request.json(); } catch {} }

    // Auth Helper
    const getAuth = async () => {
      const token = request.headers.get('Authorization')?.split(' ')[1];
      return token ? await jwtVerify(token, env.JWT_SECRET) : null;
    };

    // ── МАРШРУТЫ БЕЗ АВТОРИЗАЦИИ ──
    
    if (path === '/register' && method === 'POST') {
      const { username, name, password } = body;
      const hashed = await hashPassword(password);
      const user = await supabase.post('users', { username, name, password_hash: hashed, joined: 'апрель 2026', following: [], scores: {} });
      const token = await jwtSign({ id: user[0].id }, env.JWT_SECRET);
      return json({ token, user: user[0] });
    }

    if (path === '/login' && method === 'POST') {
      const users = await supabase.get('users', `username=eq.${body.username}`);
      if (!users[0] || !(await verifyPassword(body.password, users[0].password_hash))) return err('Ошибка входа', 401);
      const token = await jwtSign({ id: users[0].id }, env.JWT_SECRET);
      return json({ token, user: users[0] });
    }

    // ── МАРШРУТЫ С АВТОРИЗАЦИЕЙ ──
    
    const auth = await getAuth();
    if (!auth) return err('Доступ запрещен', 401);

    // Профиль
    if (path === '/me' && method === 'GET') {
      const u = await supabase.get('users', `id=eq.${auth.id}`);
      return json(u[0]);
    }

    if (path === '/me' && method === 'PATCH') {
      if (body.avatar_base64) {
        const fileName = `avatars/${auth.id}_${Date.now()}.jpg`;
        body.avatar_url = await uploadToR2(env, body.avatar_base64, fileName);
        delete body.avatar_base64;
      }
      const updated = await supabase.patch('users', body, `id=eq.${auth.id}`);
      return json(updated);
    }

    // Посты
    if (path === '/posts' && method === 'GET') {
      const posts = await supabase.get('posts', 'select=*&order=created_at.desc');
      return json(posts.map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
    }

    if (path === '/posts' && method === 'POST') {
      let image_url = null;
      if (body.image_base64) {
        image_url = await uploadToR2(env, body.image_base64, `posts/${auth.id}_${Date.now()}.jpg`);
      }
      const post = await supabase.post('posts', { user_id: auth.id, text: body.text, image_url, likes: [], comments: [] });
      return json(post);
    }

    // Чат / Сообщения
    if (path === '/messages' && method === 'GET') {
      const chatKey = [auth.id, body.userId].sort().join('-');
      const rows = await supabase.get('messages', `chat_key=eq.${chatKey}`);
      return json(rows[0]?.messages || []);
    }

    if (path === '/messages' && method === 'POST') {
      const chatKey = [auth.id, body.userId].sort().join('-');
      let image_url = null;
      if (body.image_base64) {
        image_url = await uploadToR2(env, body.image_base64, `chats/${Date.now()}.jpg`);
      }
      const newMsg = { id: Date.now().toString(36), from: auth.id, text: body.text, image_url, time: new Date().toISOString() };
      
      const existing = await supabase.get('messages', `chat_key=eq.${chatKey}`);
      if (existing[0]) {
        await supabase.patch('messages', { messages: [...existing[0].messages, newMsg] }, `chat_key=eq.${chatKey}`);
      } else {
        await supabase.post('messages', { chat_key: chatKey, user1_id: auth.id, user2_id: body.userId, messages: [newMsg] });
      }
      return json(newMsg);
    }

    // Reels (Видео)
    if (path === '/reels' && method === 'GET') {
      return json(await supabase.get('reels', 'select=*&order=created_at.desc'));
    }

    if (path === '/reels' && method === 'POST') {
      const video_url = await uploadToR2(env, body.video_base64, `reels/${auth.id}_${Date.now()}.mp4`);
      if (!video_url) return err('Ошибка загрузки видео');
      const reel = await supabase.post('reels', { user_id: auth.id, video_url, caption: body.caption, likes: [], views: 0 });
      return json(reel);
    }

    // Игры / Счета
    if (path === '/scores' && method === 'POST') {
      const u = await supabase.get('users', `id=eq.${auth.id}`);
      const scores = u[0].scores || {};
      if (!scores[body.game] || body.score > scores[body.game]) {
        scores[body.game] = body.score;
        await supabase.patch('users', { scores }, `id=eq.${auth.id}`);
      }
      return json({ best: scores[body.game] });
    }

    // Универсальная загрузка (Шаг 4)
    if (path === '/upload' && method === 'POST') {
      const url = await uploadToR2(env, body.file_base64, `${body.folder || 'misc'}/${Date.now()}_${body.name || 'file'}`);
      return json({ url });
    }

    return err('Маршрут не найден', 404);
  }
};
