function sb(env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_KEY;
  const headers = {
    'apikey': key,
    'Authorization': 'Bearer ' + key,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };

  async function query(table, opts = {}) {
    let path = '/rest/v1/' + table;
    const params = [];
    if (opts.select) params.push('select=' + encodeURIComponent(opts.select));
    if (opts.eq) Object.entries(opts.eq).forEach(([k,v]) => params.push(k + '=eq.' + encodeURIComponent(v)));
    if (opts.in) Object.entries(opts.in).forEach(([k,v]) => params.push(k + '=in.(' + v.join(',') + ')'));
    if (opts.order) params.push('order=' + opts.order);
    if (opts.limit) params.push('limit=' + opts.limit);
    if (opts.single) headers['Accept'] = 'application/vnd.pgrst.object+json';
    else delete headers['Accept'];
    if (params.length) path += '?' + params.join('&');

    const method = opts.method || 'GET';
    const fetchOpts = { method, headers: { ...headers } };
    if (opts.body) fetchOpts.body = JSON.stringify(opts.body);
    if (method === 'POST') fetchOpts.headers['Prefer'] = 'return=representation';
    if (method === 'PATCH') fetchOpts.headers['Prefer'] = 'return=representation';

    const r = await fetch(url + path, fetchOpts);
    if (!r.ok) {
      const err = await r.text();
      console.error('Supabase error:', r.status, err);
      return { data: null, error: err };
    }
    const data = await r.json();
    return { data, error: null };
  }

  return {
    from(table) {
      return {
        select(cols) { return this._q({ select: cols || '*' }); },
        insert(body) { return this._q({ method: 'POST', body }); },
        update(body) { return this._q({ method: 'PATCH', body }); },
        _q(extra) {
          let opts = { ...extra };
          return {
            eq(k, v) { opts.eq = { ...(opts.eq||{}), [k]: v }; return this; },
            in(k, v) { opts.in = { ...(opts.in||{}), [k]: v }; return this; },
            order(col, o) { opts.order = col + (o?.ascending === false ? '.desc' : '.asc'); return this; },
            limit(n) { opts.limit = n; return this; },
            single() { opts.single = true; return this; },
            then(res, rej) { return query(table, opts).then(res, rej); },
            select(cols) { opts.select = cols; return this; }
          };
        }
      };
    }
  };
}

// ── JWT (без npm — Web Crypto API) ───────────────────────────
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
    const payload = JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
    if (payload.exp && payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

// ── bcrypt-совместимый хэш (используем scrypt через Web Crypto) ──
// Cloudflare Workers не поддерживают bcrypt, используем SHA-256 с солью
// ВАЖНО: Это означает что старые bcrypt-пароли из Vercel НЕ будут работать!
// Все пользователи должны перерегистрироваться (или сбросить пароль)
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2,'0')).join('');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
  return 'pbkdf2:' + saltHex + ':' + hash;
}

async function verifyPassword(password, stored) {
  // Поддержка обоих форматов
  if (!stored) return false;
  if (stored.startsWith('pbkdf2:')) {
    const [, saltHex, storedHash] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
    const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
    return hash === storedHash;
  }
  // Старый bcrypt хэш — не совместим, вернём false
  return false;
}

// ── Утилиты ──────────────────────────────────────────────────
function cors(headers = {}) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...headers
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: cors({ 'Content-Type': 'application/json' })
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

function formatTime(isoStr) {
  const d = new Date(isoStr), now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60) return 'только что';
  if (diff < 3600) return Math.floor(diff/60) + 'м назад';
  if (diff < 86400) return Math.floor(diff/3600) + 'ч назад';
  if (diff < 604800) return Math.floor(diff/86400) + 'д назад';
  return d.toLocaleDateString('ru');
}

function chatKey(a, b) { return [a, b].sort((x,y) => x-y).join('-'); }

function safeUser(u) {
  if (!u) return null;
  const { password_hash, ...safe } = u;
  return safe;
}

function msgId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2,6);
}

// ── Загрузка файла в Supabase Storage ────────────────────────
async function uploadToStorage(env, fileData, filename, contentType) {
  try {
    const path = filename;
    const r = await fetch(env.SUPABASE_URL + '/storage/v1/object/media/' + path, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY,
        'Content-Type': contentType || 'application/octet-stream',
        'x-upsert': 'true'
      },
      body: fileData
    });
    if (!r.ok) {
      const err = await r.text();
      console.error('Storage upload error:', err);
      return null;
    }
    return env.SUPABASE_URL + '/storage/v1/object/public/media/' + path;
  } catch(e) {
    console.error('Storage upload error:', e);
    return null;
  }
}
// Псевдоним для обратной совместимости
const uploadToR2 = uploadToStorage;

// Конвертация base64 → ArrayBuffer
function base64ToBuffer(base64) {
  const base64Data = base64.includes(',') ? base64.split(',')[1] : base64;
  const binary = atob(base64Data);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
  return buffer.buffer;
}

function getContentType(base64) {
  const match = base64.match(/^data:([^;]+);/);
  return match ? match[1] : 'application/octet-stream';
}

// ── ГЛАВНЫЙ ОБРАБОТЧИК ────────────────────────────────────────
export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    const supabase = sb(env);
    const JWT_SECRET = env.JWT_SECRET || 'volna_dev_secret';

    const reqUrl = new URL(request.url);
    const path = reqUrl.pathname.replace(/^\/api/, '');
    const method = request.method;
    const query = Object.fromEntries(reqUrl.searchParams);

    // Парсим body
    let body = {};
    if (['POST','PATCH','PUT'].includes(method)) {
      try { body = await request.json(); } catch {}
    }

    // Получаем текущего пользователя
    async function getAuthUser() {
      const token = request.headers.get('Authorization')?.split(' ')[1];
      if (!token) return null;
      return await jwtVerify(token, JWT_SECRET);
    }

    // ── POST /api/register ──────────────────────────────────
    if (path === '/register' && method === 'POST') {
      const { username, name, password } = body;
      if (!username || !name || !password) return err('Заполни все поля');
      if (password.length < 4) return err('Пароль минимум 4 символа');
      if (!/^[a-zA-Z0-9_]+$/.test(username)) return err('Только латиница, цифры и _');

      const { data: existing } = await supabase.from('users').select('id').eq('id', 0)
        ._q({ select: 'id', eq: { username } }).single();
      // ↑ Более прямой запрос:
      const chk = await fetch(env.SUPABASE_URL + '/rest/v1/users?select=id&username=eq.' + encodeURIComponent(username), {
        headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY }
      });
      const chkData = await chk.json();
      if (chkData.length > 0) return err('Это имя уже занято');

      const passwordHash = await hashPassword(password);
      const months = ['январь','февраль','март','апрель','май','июнь','июль','август','сентябрь','октябрь','ноябрь','декабрь'];
      const now = new Date();
      const joined = months[now.getMonth()] + ' ' + now.getFullYear();

      const insRes = await fetch(env.SUPABASE_URL + '/rest/v1/users', {
        method: 'POST',
        headers: {
          'apikey': env.SUPABASE_SERVICE_KEY,
          'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation'
        },
        body: JSON.stringify({ username, name, password_hash: passwordHash, bio: '', joined, following: [], scores: {} })
      });
      if (!insRes.ok) return err('Ошибка сервера', 500);
      const users = await insRes.json();
      const user = Array.isArray(users) ? users[0] : users;
      const token = await jwtSign({ id: user.id, exp: Math.floor(Date.now()/1000) + 30*24*3600 }, JWT_SECRET);
      return json({ token, user: safeUser(user) });
    }

    // ── POST /api/login ─────────────────────────────────────
    if (path === '/login' && method === 'POST') {
      const { username, password } = body;
      const r = await fetch(env.SUPABASE_URL + '/rest/v1/users?username=eq.' + encodeURIComponent(username), {
        headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY }
      });
      const users = await r.json();
      const user = users[0];
      if (!user) return err('Неверный логин или пароль', 401);
      const ok = await verifyPassword(password, user.password_hash);
      if (!ok) return err('Неверный логин или пароль', 401);
      const token = await jwtSign({ id: user.id, exp: Math.floor(Date.now()/1000) + 30*24*3600 }, JWT_SECRET);
      return json({ token, user: safeUser(user) });
    }

    // ── Всё ниже требует авторизации ────────────────────────
    const authUser = await getAuthUser();
    if (!authUser) return err('Нет доступа', 401);

    const supa = {
      async get(table, params) {
        let u = env.SUPABASE_URL + '/rest/v1/' + table + '?';
        if (params) u += params;
        const r = await fetch(u, { headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY } });
        return r.json();
      },
      async post(table, data) {
        const r = await fetch(env.SUPABASE_URL + '/rest/v1/' + table, {
          method: 'POST',
          headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json', 'Prefer': 'return=representation' },
          body: JSON.stringify(data)
        });
        const d = await r.json();
        return Array.isArray(d) ? d[0] : d;
      },
      async patch(table, data, filter) {
        const r = await fetch(env.SUPABASE_URL + '/rest/v1/' + table + '?' + filter, {
          method: 'PATCH',
          headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json', 'Prefer': 'return=representation' },
          body: JSON.stringify(data)
        });
        const d = await r.json();
        return Array.isArray(d) ? d[0] : d;
      }
    };

    // ── GET /api/me ─────────────────────────────────────────
    if (path === '/me' && method === 'GET') {
      const users = await supa.get('users', 'select=id,username,name,bio,joined,interests,banner_color,following,avatar_url,scores&id=eq.' + authUser.id);
      return json(users[0] || {});
    }

    // ── PATCH /api/me ────────────────────────────────────────
    if (path === '/me' && method === 'PATCH') {
      const { name, bio, interests, banner_color, avatar_base64, liked_tracks, playlist } = body;
      const updates = {};
      if (name) updates.name = name;
      if (bio !== undefined) updates.bio = bio;
      if (interests !== undefined) updates.interests = interests;
      if (banner_color !== undefined) updates.banner_color = banner_color;
      if (liked_tracks !== undefined) updates.liked_tracks = liked_tracks;
      if (playlist !== undefined) updates.playlist = playlist;

      // Загружаем аватар в Supabase Storage
      if (avatar_base64) {
        const ct = getContentType(avatar_base64);
        const ext = ct.split('/')[1] || 'jpg';
        const filename = 'avatars/' + authUser.id + '.' + ext;
        const url = await uploadToR2(env, base64ToBuffer(avatar_base64), filename, ct);
        if (url) updates.avatar_url = url;
        else updates.avatar_url = avatar_base64; // fallback
      }

      const updated = await supa.patch('users', updates, 'id=eq.' + authUser.id);
      return json(safeUser(updated) || {});
    }

    // ── GET /api/users ───────────────────────────────────────
    if (path === '/users' && method === 'GET') {
      const users = await supa.get('users', 'select=id,username,name,bio,following,avatar_url,banner_color,joined,interests');
      return json(users || []);
    }

    // ── POST /api/follow?id=X ────────────────────────────────
    if (path === '/follow' && method === 'POST') {
      const targetId = parseInt(query.id);
      const me = await supa.get('users', 'select=following&id=eq.' + authUser.id);
      let following = me[0]?.following || [];
      const idx = following.indexOf(targetId);
      if (idx === -1) following.push(targetId); else following.splice(idx, 1);
      await supa.patch('users', { following }, 'id=eq.' + authUser.id);
      return json({ following });
    }

    // ── GET /api/posts ───────────────────────────────────────
    if (path === '/posts' && method === 'GET') {
      if (query.userId === 'all') {
        const posts = await supa.get('posts', 'select=*&order=created_at.desc&limit=100');
        return json((posts||[]).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
      }
      if (query.userId) {
        const posts = await supa.get('posts', 'select=*&user_id=eq.' + parseInt(query.userId) + '&order=created_at.desc');
        return json((posts||[]).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
      }
      const me = await supa.get('users', 'select=following&id=eq.' + authUser.id);
      const ids = [authUser.id, ...(me[0]?.following || [])];
      const posts = await supa.get('posts', 'select=*&user_id=in.(' + ids.join(',') + ')&order=created_at.desc');
      return json((posts||[]).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
    }

    // ── POST /api/posts ──────────────────────────────────────
    if (path === '/posts' && method === 'POST') {
      const { text, image_base64 } = body;
      if (!text?.trim() && !image_base64) return err('Текст или фото обязательны');

      let image_url = null;
      // Загружаем фото в Supabase Storage
      if (image_base64) {
        const ct = getContentType(image_base64);
        const ext = ct.split('/')[1] || 'jpg';
        const filename = 'posts/' + Date.now() + '_' + authUser.id + '.' + ext;
        image_url = await uploadToR2(env, base64ToBuffer(image_base64), filename, ct);
        if (!image_url) image_url = image_base64; // fallback
      }

      const post = await supa.post('posts', {
        user_id: authUser.id,
        text: text?.trim() || '',
        likes: [], comments: [],
        image_url
      });
      return json({ ...post, timeFormatted: 'только что' });
    }

    // ── POST /api/post-action?id=X&action=like|comment ───────
    if (path === '/post-action' && method === 'POST') {
      const postId = parseInt(query.id);
      const posts = await supa.get('posts', 'select=*&id=eq.' + postId);
      const post = posts[0];
      if (!post) return err('Пост не найден', 404);

      if (query.action === 'like') {
        let likes = post.likes || [];
        const idx = likes.indexOf(authUser.id);
        if (idx === -1) likes.push(authUser.id); else likes.splice(idx, 1);
        await supa.patch('posts', { likes }, 'id=eq.' + postId);
        return json({ likes });
      }
      if (query.action === 'comment') {
        const { text } = body;
        if (!text?.trim()) return err('Текст пуст');
        const comment = { userId: authUser.id, text: text.trim(), time: new Date().toISOString() };
        const comments = [...(post.comments||[]), comment];
        await supa.patch('posts', { comments }, 'id=eq.' + postId);
        return json(comment);
      }
      return err('Неизвестное действие');
    }

    // ── POST /api/heartbeat ──────────────────────────────────
    if (path === '/heartbeat' && method === 'POST') {
      await supa.patch('presence', { last_seen: new Date().toISOString() }, 'user_id=eq.' + authUser.id).catch(() => {});
      await fetch(env.SUPABASE_URL + '/rest/v1/presence', {
        method: 'POST',
        headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ user_id: authUser.id, last_seen: new Date().toISOString() })
      });
      return json({ ok: true });
    }

    // ── GET /api/online?ids=1,2,3 ────────────────────────────
    if (path === '/online' && method === 'GET') {
      const ids = (query.ids||'').split(',').map(Number).filter(Boolean);
      if (!ids.length) return json({});
      const since = new Date(Date.now() - 20000).toISOString();
      const rows = await supa.get('presence', 'select=user_id,last_seen&user_id=in.(' + ids.join(',') + ')&last_seen=gte.' + since);
      const result = {};
      (rows||[]).forEach(r => { result[r.user_id] = true; });
      return json(result);
    }

    // ── POST /api/typing?to=X ────────────────────────────────
    if (path === '/typing' && method === 'POST') {
      const toId = parseInt(query.to);
      await fetch(env.SUPABASE_URL + '/rest/v1/presence', {
        method: 'POST',
        headers: { 'apikey': env.SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ user_id: authUser.id, last_seen: new Date().toISOString(), typing_to: toId, typing_at: new Date().toISOString() })
      });
      return json({ ok: true });
    }

    // ── GET /api/typing?from=X ───────────────────────────────
    if (path === '/typing' && method === 'GET') {
      const fromId = parseInt(query.from);
      const rows = await supa.get('presence', 'select=typing_to,typing_at&user_id=eq.' + fromId);
      const d = rows[0];
      const typing = d && d.typing_to === authUser.id && d.typing_at && new Date(d.typing_at) > new Date(Date.now() - 3500);
      return json({ typing: !!typing });
    }

    // ── GET /api/messages ── список чатов ────────────────────
    if (path === '/messages' && method === 'GET' && !query.userId) {
      const rows = await supa.get('messages', 'select=*&or=(user1_id.eq.' + authUser.id + ',user2_id.eq.' + authUser.id + ')');
      const convos = await Promise.all((rows||[]).map(async row => {
        const otherId = row.user1_id === authUser.id ? row.user2_id : row.user1_id;
        const users = await supa.get('users', 'select=id,name,username&id=eq.' + otherId);
        const other = users[0];
        const msgs = row.messages || [];
        const last = msgs.length ? msgs[msgs.length-1] : null;
        return { userId: otherId, name: other?.name||'', username: other?.username||'', lastMessage: last?.text||'', lastTime: last?.time||'' };
      }));
      return json(convos);
    }

    // ── GET /api/messages?userId=X ───────────────────────────
    if (path === '/messages' && method === 'GET' && query.userId) {
      const otherId = parseInt(query.userId);
      const key = chatKey(authUser.id, otherId);
      const rows = await supa.get('messages', 'select=messages&chat_key=eq.' + key);
      const msgs = (rows[0]?.messages||[]).map(m => ({
        ...m,
        timeFormatted: new Date(m.time).toLocaleTimeString('ru', { hour:'2-digit', minute:'2-digit' })
      }));
      return json(msgs);
    }

    // ── POST /api/messages?userId=X ── отправить ─────────────
    if (path === '/messages' && method === 'POST' && query.userId && !query.action) {
      const otherId = parseInt(query.userId);
      const { text, image_base64 } = body;
      if (!text?.trim() && !image_base64) return err('Пусто');

      let image_url = null;
      if (image_base64) {
        const ct = getContentType(image_base64);
        const ext = ct.split('/')[1] || 'jpg';
        const filename = 'messages/' + msgId() + '.' + ext;
        image_url = await uploadToR2(env, base64ToBuffer(image_base64), filename, ct);
        if (!image_url) image_url = image_base64;
      }

      const key = chatKey(authUser.id, otherId);
      const rows = await supa.get('messages', 'select=*&chat_key=eq.' + key);
      const existing = rows[0];
      const newMsg = { id: msgId(), from: authUser.id, text: text?.trim()||'', image_url, time: new Date().toISOString() };

      if (existing) {
        await supa.patch('messages', { messages: [...(existing.messages||[]), newMsg] }, 'chat_key=eq.' + key);
      } else {
        const [u1,u2] = key.split('-').map(Number);
        await supa.post('messages', { chat_key: key, user1_id: u1, user2_id: u2, messages: [newMsg] });
      }
      return json({ ...newMsg, timeFormatted: new Date(newMsg.time).toLocaleTimeString('ru', { hour:'2-digit', minute:'2-digit' }) });
    }

    // ── DELETE /api/messages?userId=X&msgId=Y ────────────────
    if (path === '/messages' && method === 'DELETE' && query.userId) {
      const otherId = parseInt(query.userId);
      const key = chatKey(authUser.id, otherId);
      const rows = await supa.get('messages', 'select=*&chat_key=eq.' + key);
      const row = rows[0];
      if (!row) return err('Чат не найден', 404);
      const msgs = row.messages||[];
      const idx = query.msgId ? msgs.findIndex(m => m.id === query.msgId) : parseInt(query.msgIdx||'-1');
      if (idx < 0 || idx >= msgs.length) return err('Не найдено', 404);
      if (msgs[idx].from !== authUser.id) return err('Нельзя удалить чужое', 403);
      msgs[idx] = { ...msgs[idx], deleted: true, text: '', image_url: null };
      await supa.patch('messages', { messages: msgs }, 'chat_key=eq.' + key);
      return json({ ok: true });
    }

    // ── PATCH /api/messages?userId=X&msgId=Y ─────────────────
    if (path === '/messages' && method === 'PATCH' && query.userId) {
      const otherId = parseInt(query.userId);
      const { text } = body;
      if (!text?.trim()) return err('Пусто');
      const key = chatKey(authUser.id, otherId);
      const rows = await supa.get('messages', 'select=*&chat_key=eq.' + key);
      const row = rows[0];
      if (!row) return err('Чат не найден', 404);
      const msgs = row.messages||[];
      const idx = query.msgId ? msgs.findIndex(m => m.id === query.msgId) : parseInt(query.msgIdx||'-1');
      if (idx < 0 || idx >= msgs.length) return err('Не найдено', 404);
      if (msgs[idx].from !== authUser.id) return err('Нельзя редактировать чужое', 403);
      msgs[idx] = { ...msgs[idx], text: text.trim(), edited: true };
      await supa.patch('messages', { messages: msgs }, 'chat_key=eq.' + key);
      return json({ ok: true });
    }

    // ── POST /api/messages?userId=X&msgId=Y&action=react ─────
    if (path === '/messages' && method === 'POST' && query.userId && query.action === 'react') {
      const otherId = parseInt(query.userId);
      const { emoji } = body;
      if (!emoji) return err('Нет эмодзи');
      const key = chatKey(authUser.id, otherId);
      const rows = await supa.get('messages', 'select=*&chat_key=eq.' + key);
      const row = rows[0];
      if (!row) return err('Чат не найден', 404);
      const msgs = row.messages||[];
      const idx = query.msgId ? msgs.findIndex(m => m.id === query.msgId) : parseInt(query.msgIdx||'-1');
      if (idx < 0 || idx >= msgs.length) return err('Не найдено', 404);
      const reactions = msgs[idx].reactions||{};
      if (!reactions[emoji]) reactions[emoji] = [];
      const ui = reactions[emoji].indexOf(authUser.id);
      if (ui === -1) reactions[emoji].push(authUser.id); else reactions[emoji].splice(ui,1);
      if (!reactions[emoji].length) delete reactions[emoji];
      msgs[idx] = { ...msgs[idx], reactions };
      await supa.patch('messages', { messages: msgs }, 'chat_key=eq.' + key);
      return json({ reactions });
    }

    // ── GET /api/reels ───────────────────────────────────────
    if (path === '/reels' && method === 'GET') {
      const reels = await supa.get('reels', 'select=*&order=created_at.desc&limit=50');
      return json(reels||[]);
    }

    // ── POST /api/reels ──────────────────────────────────────
    if (path === '/reels' && method === 'POST') {
      const { video_base64, caption } = body;
      if (!video_base64) return err('Видео обязательно');

      const ct = getContentType(video_base64) || 'video/mp4';
      const ext = ct.split('/')[1] || 'mp4';
      const filename = 'reels/' + Date.now() + '_' + authUser.id + '.' + ext;
      let video_url = await uploadToR2(env, base64ToBuffer(video_base64), filename, ct);
      if (!video_url) return err('Ошибка загрузки видео', 500);

      const reel = await supa.post('reels', {
        user_id: authUser.id, video_url, caption: caption?.trim()||'', likes: [], views: 0
      });
      return json(reel);
    }

    // ── POST /api/reels-action?id=X&action=like|view ─────────
    if (path === '/reels-action' && method === 'POST') {
      const reelId = parseInt(query.id);
      const reels = await supa.get('reels', 'select=*&id=eq.' + reelId);
      const reel = reels[0];
      if (!reel) return err('Не найдено', 404);
      if (query.action === 'like') {
        let likes = reel.likes||[];
        const idx = likes.indexOf(authUser.id);
        if (idx === -1) likes.push(authUser.id); else likes.splice(idx,1);
        await supa.patch('reels', { likes }, 'id=eq.' + reelId);
        return json({ likes });
      }
      if (query.action === 'view') {
        await supa.patch('reels', { views: (reel.views||0)+1 }, 'id=eq.' + reelId);
        return json({ ok: true });
      }
      return err('Неизвестное действие');
    }

    // ── GET /api/scores ──────────────────────────────────────
    if (path === '/scores' && method === 'GET') {
      const users = await supa.get('users', 'select=scores&id=eq.' + authUser.id);
      return json(users[0]?.scores||{});
    }

    // ── POST /api/scores?game=X&score=Y ─────────────────────
    if (path === '/scores' && method === 'POST') {
      const game = query.game, newScore = parseInt(query.score);
      if (!game || isNaN(newScore)) return err('Нет данных');
      const users = await supa.get('users', 'select=scores&id=eq.' + authUser.id);
      const scores = users[0]?.scores||{};
      if (!scores[game] || newScore > scores[game]) {
        scores[game] = newScore;
        await supa.patch('users', { scores }, 'id=eq.' + authUser.id);
      }
      return json({ best: scores[game] });
    }

    // ── POST /api/upload ── прямая загрузка файла в Storage ───────
    if (path === '/upload' && method === 'POST') {
      const { file_base64, folder, name } = body;
      if (!file_base64) return err('Нет файла');
      const ct = getContentType(file_base64);
      const ext = ct.split('/')[1] || 'bin';
      const filename = (folder||'uploads') + '/' + (name || (Date.now() + '_' + authUser.id)) + '.' + ext;
      const url = await uploadToR2(env, base64ToBuffer(file_base64), filename, ct);
      if (!url) return err('Ошибка загрузки', 500);
      return json({ url });
    }

    return err('Не найдено', 404);
  }
};
