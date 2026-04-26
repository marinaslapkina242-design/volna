import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Supabase-совместимый интерфейс для PostgreSQL
const supabase = {
  from: (table) => new SupabaseQuery(table)
};

class SupabaseQuery {
  constructor(table) {
    this.table = table;
    this._select = '*';
    this._conditions = [];
    this._order = null;
    this._limit = null;
    this._single = false;
    this._method = 'SELECT';
    this._body = null;
    this._inConditions = [];
    this._orConditions = [];
  }
  select(cols) { this._select = cols || '*'; return this; }
  eq(col, val) { this._conditions.push({ col, val }); return this; }
  in(col, vals) { this._inConditions.push({ col, vals }); return this; }
  or(str) { this._orConditions.push(str); return this; }
  gte(col, val) { this._conditions.push({ col, val, op: '>=' }); return this; }
  order(col, opts) { this._order = { col, desc: opts?.ascending === false }; return this; }
  limit(n) { this._limit = n; return this; }
  single() { this._single = true; return this; }
  insert(body) { this._method = 'INSERT'; this._body = body; return this; }
  update(body) { this._method = 'UPDATE'; this._body = body; return this; }
  upsert(body, opts) { this._method = 'UPSERT'; this._body = body; this._upsertOpts = opts; return this; }
  delete() { this._method = 'DELETE'; return this; }

  async _run() {
    const client = await pool.connect();
    try {
      if (this._method === 'SELECT') {
        let params = [];
        let where = [];
        for (const c of this._conditions) {
          params.push(c.val);
          where.push(`"${c.col}" ${c.op||'='} $${params.length}`);
        }
        for (const c of this._inConditions) {
          params.push(c.vals);
          where.push(`"${c.col}" = ANY($${params.length})`);
        }
        for (const orStr of this._orConditions) {
          const parts = orStr.split(',').map(p => {
            const m = p.match(/(\w+)\.(eq|gte)\.(.+)/);
            if (!m) return null;
            params.push(m[3]);
            return `"${m[1]}" ${m[2]==='eq'?'=':'>='} $${params.length}`;
          }).filter(Boolean);
          if (parts.length) where.push('(' + parts.join(' OR ') + ')');
        }
        let q = \`SELECT \${this._select === '*' ? '*' : this._select.split(',').map(c=>c.trim()).map(c=>\`"\${c}"\`).join(',')} FROM "\${this.table}"\`;
        if (where.length) q += ' WHERE ' + where.join(' AND ');
        if (this._order) q += \` ORDER BY "\${this._order.col}" \${this._order.desc?'DESC':'ASC'}\`;
        if (this._limit) q += \` LIMIT \${this._limit}\`;
        const res = await client.query(q, params);
        const data = this._single ? (res.rows[0] || null) : res.rows;
        return { data, error: null };
      }
      if (this._method === 'INSERT') {
        const body = Array.isArray(this._body) ? this._body : [this._body];
        const results = [];
        for (const row of body) {
          const keys = Object.keys(row);
          const vals = Object.values(row);
          const q = \`INSERT INTO "\${this.table}" (\${keys.map(k=>\`"\${k}"\`).join(',')}) VALUES (\${vals.map((_,i)=>'$'+(i+1)).join(',')}) RETURNING *\`;
          const res = await client.query(q, vals);
          results.push(res.rows[0]);
        }
        const data = this._single ? results[0] : results;
        return { data, error: null };
      }
      if (this._method === 'UPDATE') {
        const keys = Object.keys(this._body);
        const vals = Object.values(this._body);
        let params = [...vals];
        const sets = keys.map((k,i) => \`"\${k}"=$\${i+1}\`).join(',');
        let where = this._conditions.map(c => { params.push(c.val); return \`"\${c.col}"=$\${params.length}\`; });
        let q = \`UPDATE "\${this.table}" SET \${sets}\`;
        if (where.length) q += ' WHERE ' + where.join(' AND ');
        q += ' RETURNING *';
        const res = await client.query(q, params);
        const data = this._single ? (res.rows[0]||null) : res.rows;
        return { data, error: null };
      }
      if (this._method === 'UPSERT') {
        const body = this._body;
        const keys = Object.keys(body);
        const vals = Object.values(body);
        const conflict = this._upsertOpts?.onConflict || 'id';
        const sets = keys.filter(k=>k!==conflict).map((k,i)=>\`"\${k}"=EXCLUDED."\${k}"\`).join(',');
        const q = \`INSERT INTO "\${this.table}" (\${keys.map(k=>\`"\${k}"\`).join(',')}) VALUES (\${vals.map((_,i)=>'$'+(i+1)).join(',')}) ON CONFLICT ("\${conflict}") DO UPDATE SET \${sets} RETURNING *\`;
        const res = await client.query(q, vals);
        return { data: res.rows[0], error: null };
      }
      return { data: null, error: 'Unknown method' };
    } catch(e) {
      console.error('DB error:', e.message);
      return { data: null, error: e.message };
    } finally {
      client.release();
    }
  }
  then(resolve, reject) { return this._run().then(resolve, reject); }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));

const __dirname = dirname(fileURLToPath(import.meta.url));
const JWT_SECRET = process.env.JWT_SECRET || 'volna_secret_2025';

// ── Утилиты ──
function getUser(req) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function safeUser(u) {
  const { password_hash, ...safe } = u;
  return safe;
}
function formatTime(isoStr) {
  const d = new Date(isoStr), now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60) return 'только что';
  if (diff < 3600) return `${Math.floor(diff / 60)}м назад`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}ч назад`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}д назад`;
  return d.toLocaleDateString('ru');
}
function chatKey(a, b) { return [a, b].sort((x, y) => x - y).join('-'); }
function auth(req, res) {
  const u = getUser(req);
  if (!u) { res.status(401).json({ error: 'Нет доступа' }); return null; }
  return u;
}

// ── POST /api/register ──
app.post('/api/register', async (req, res) => {
  const { username, name, password } = req.body;
  if (!username || !name || !password)
    return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Только латиница, цифры и _' });

  const { data: existing } = await supabase
    .from('users').select('id').eq('username', username).single();
  if (existing) return res.status(400).json({ error: 'Это имя уже занято' });

  const passwordHash = bcrypt.hashSync(password, 10);
  const now = new Date();
  const months = ['январь','февраль','март','апрель','май','июнь','июль','август','сентябрь','октябрь','ноябрь','декабрь'];
  const joined = months[now.getMonth()] + ' ' + now.getFullYear();

  const { data: user, error } = await supabase
    .from('users')
    .insert({ username, name, password_hash: passwordHash, bio: '', joined })
    .select().single();
  if (error) return res.status(500).json({ error: 'Ошибка сервера' });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// ── POST /api/login ──
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('username', username).single();
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// ── GET /api/me ──
app.get('/api/me', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { data } = await supabase
    .from('users')
    .select('id, username, name, bio, joined, interests, banner_color, following, avatar_url, avatar_base64, liked_tracks, playlist')
    .eq('id', me.id).single();
  res.json(data);
});

// ── PATCH /api/me ──
app.patch('/api/me', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { name, bio, interests, banner_color, avatar_base64, avatar_url, liked_tracks, playlist } = req.body;
  const updates = {};
  if (name) updates.name = name;
  if (bio !== undefined) updates.bio = bio;
  if (interests !== undefined) updates.interests = interests;
  if (banner_color !== undefined) updates.banner_color = banner_color;
  if (avatar_base64 !== undefined) updates.avatar_base64 = avatar_base64;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  if (liked_tracks !== undefined) updates.liked_tracks = liked_tracks;
  if (playlist !== undefined) updates.playlist = playlist;
  const { data } = await supabase
    .from('users').update(updates).eq('id', me.id)
    .select('id, username, name, bio, joined, interests, banner_color, following, avatar_url, avatar_base64, liked_tracks, playlist').single();
  res.json(data);
});

// ── GET /api/users ──
app.get('/api/users', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { data } = await supabase
    .from('users').select('id, username, name, bio, following, avatar_url, avatar_base64, banner_color, joined, interests');
  res.json(data || []);
});

// ── POST /api/follow ──
app.post('/api/follow', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const targetId = parseInt(req.query.id);
  const { data: user } = await supabase
    .from('users').select('following').eq('id', me.id).single();
  let following = user.following || [];
  const idx = following.indexOf(targetId);
  if (idx === -1) following.push(targetId); else following.splice(idx, 1);
  await supabase.from('users').update({ following }).eq('id', me.id);
  res.json({ following });
});

// ── GET /api/posts ──
app.get('/api/posts', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { userId } = req.query;
  if (userId === 'all') {
    const { data } = await supabase.from('posts').select('*')
      .order('created_at', { ascending: false }).limit(100);
    return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
  }
  if (userId) {
    const { data } = await supabase.from('posts').select('*')
      .eq('user_id', parseInt(userId)).order('created_at', { ascending: false });
    return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
  }
  const { data: user } = await supabase.from('users').select('following').eq('id', me.id).single();
  const ids = [me.id, ...(user.following || [])];
  const { data } = await supabase.from('posts').select('*').in('user_id', ids)
    .order('created_at', { ascending: false });
  res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
});

// ── POST /api/posts ──
app.post('/api/posts', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { text, image_url, image_base64 } = req.body;
  if (!text?.trim() && !image_url && !image_base64)
    return res.status(400).json({ error: 'Текст или фото обязательны' });
  const { data, error } = await supabase.from('posts')
    .insert({ user_id: me.id, text: text?.trim() || '', likes: [], comments: [], image_url: image_url || null, image_base64: image_base64 || null })
    .select().single();
  if (error) return res.status(500).json({ error: 'Ошибка' });
  res.json({ ...data, timeFormatted: 'только что' });
});

// ── POST /api/post-action ──
app.post('/api/post-action', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const postId = parseInt(req.query.id);
  const action = req.query.action;
  const { data: post } = await supabase.from('posts').select('*').eq('id', postId).single();
  if (!post) return res.status(404).json({ error: 'Пост не найден' });

  if (action === 'like') {
    let likes = post.likes || [];
    const idx = likes.indexOf(me.id);
    if (idx === -1) likes.push(me.id); else likes.splice(idx, 1);
    await supabase.from('posts').update({ likes }).eq('id', postId);
    return res.json({ likes });
  }
  if (action === 'comment') {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
    const comments = [...(post.comments || []), { userId: me.id, text: text.trim(), time: new Date().toISOString() }];
    await supabase.from('posts').update({ comments }).eq('id', postId);
    return res.json({ comments });
  }
  if (action === 'delete') {
    if (post.user_id !== me.id) return res.status(403).json({ error: 'Нельзя' });
    await supabase.from('posts').delete().eq('id', postId);
    return res.json({ ok: true });
  }
  res.status(400).json({ error: 'Неизвестное действие' });
});

// ── GET /api/messages (список чатов) ──
app.get('/api/messages', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { userId, msgId } = req.query;

  if (userId) {
    const key = chatKey(me.id, parseInt(userId));
    const { data: row } = await supabase.from('messages').select('messages').eq('chat_key', key).single();
    const msgs = (row?.messages || []).map(m => ({
      ...m,
      timeFormatted: new Date(m.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    }));
    return res.json(msgs);
  }

  // Список всех чатов
  const { data: rows } = await supabase.from('messages')
    .select('*').or(`user1_id.eq.${me.id},user2_id.eq.${me.id}`);
  const convos = (rows || []).map(row => {
    const msgs = row.messages || [];
    const last = msgs[msgs.length - 1];
    const otherId = row.user1_id === me.id ? row.user2_id : row.user1_id;
    return { chatKey: row.chat_key, otherId, lastMessage: last?.text || '', lastTime: last ? formatTime(last.time) : '', unread: msgs.filter(m => m.from !== me.id && !m.read).length };
  });
  res.json(convos);
});

// ── POST /api/messages ──
app.post('/api/messages', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  if (req.query.action === 'react') {
    const otherId = parseInt(req.query.userId);
    const msgId = req.query.msgId;
    const { emoji } = req.body;
    if (!emoji) return res.status(400).json({ error: 'Нет эмодзи' });
    const key = chatKey(me.id, otherId);
    const { data: row } = await supabase.from('messages').select('*').eq('chat_key', key).single();
    if (!row) return res.status(404).json({ error: 'Чат не найден' });
    const msgs = row.messages || [];
    const idx = msgs.findIndex(m => m.id === msgId);
    if (idx === -1) return res.status(404).json({ error: 'Не найдено' });
    const reactions = msgs[idx].reactions || {};
    if (!reactions[emoji]) reactions[emoji] = [];
    const ui = reactions[emoji].indexOf(me.id);
    if (ui === -1) reactions[emoji].push(me.id); else reactions[emoji].splice(ui, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    msgs[idx] = { ...msgs[idx], reactions };
    await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
    return res.json({ reactions });
  }

  const otherId = parseInt(req.query.userId);
  const { text, image_base64 } = req.body;
  if (!text?.trim() && !image_base64) return res.status(400).json({ error: 'Пусто' });
  const key = chatKey(me.id, otherId);
  const { data: existing } = await supabase.from('messages').select('*').eq('chat_key', key).single();
  const newMsg = { id: Date.now().toString(36) + Math.random().toString(36).slice(2,6), from: me.id, text: text?.trim() || '', image_base64: image_base64 || null, time: new Date().toISOString() };
  if (existing) {
    await supabase.from('messages').update({ messages: [...(existing.messages || []), newMsg] }).eq('chat_key', key);
  } else {
    const [u1, u2] = key.split('-').map(Number);
    await supabase.from('messages').insert({ chat_key: key, user1_id: u1, user2_id: u2, messages: [newMsg] });
  }
  res.json({ ...newMsg, timeFormatted: new Date(newMsg.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' }) });
});

// ── DELETE /api/messages ──
app.delete('/api/messages', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const otherId = parseInt(req.query.userId);
  const msgId = req.query.msgId;
  const key = chatKey(me.id, otherId);
  const { data: row } = await supabase.from('messages').select('*').eq('chat_key', key).single();
  if (!row) return res.status(404).json({ error: 'Чат не найден' });
  const msgs = row.messages || [];
  const idx = msgs.findIndex(m => m.id === msgId);
  if (idx === -1) return res.status(404).json({ error: 'Не найдено' });
  if (msgs[idx].from !== me.id) return res.status(403).json({ error: 'Нельзя удалить чужое' });
  msgs[idx] = { ...msgs[idx], deleted: true, text: '', image_base64: null };
  await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
  res.json({ ok: true });
});

// ── PATCH /api/messages ──
app.patch('/api/messages', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const otherId = parseInt(req.query.userId);
  const msgId = req.query.msgId;
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
  const key = chatKey(me.id, otherId);
  const { data: row } = await supabase.from('messages').select('*').eq('chat_key', key).single();
  if (!row) return res.status(404).json({ error: 'Чат не найден' });
  const msgs = row.messages || [];
  const idx = msgs.findIndex(m => m.id === msgId);
  if (idx === -1) return res.status(404).json({ error: 'Не найдено' });
  if (msgs[idx].from !== me.id) return res.status(403).json({ error: 'Нельзя редактировать чужое' });
  msgs[idx] = { ...msgs[idx], text: text.trim(), edited: true };
  await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
  res.json({ ok: true, text: text.trim() });
});

// ── GET /api/reels ──
app.get('/api/reels', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { data } = await supabase.from('reels').select('*').order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

// ── POST /api/reels ──
app.post('/api/reels', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { video_url, video_base64, caption } = req.body;
  if (!video_url && !video_base64) return res.status(400).json({ error: 'Видео обязательно' });
  const { data, error } = await supabase.from('reels')
    .insert({ user_id: me.id, video_url: video_url || null, video_base64: video_base64 || null, caption: caption?.trim() || '', likes: [], views: 0 })
    .select().single();
  if (error) return res.status(500).json({ error: 'Ошибка загрузки' });
  res.json(data);
});

// ── POST /api/reels-action ──
app.post('/api/reels-action', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const reelId = parseInt(req.query.id);
  const action = req.query.action;
  const { data: reel } = await supabase.from('reels').select('*').eq('id', reelId).single();
  if (!reel) return res.status(404).json({ error: 'Не найдено' });
  if (action === 'like') {
    let likes = reel.likes || [];
    const idx = likes.indexOf(me.id);
    if (idx === -1) likes.push(me.id); else likes.splice(idx, 1);
    await supabase.from('reels').update({ likes }).eq('id', reelId);
    return res.json({ likes });
  }
  if (action === 'view') {
    await supabase.from('reels').update({ views: (reel.views || 0) + 1 }).eq('id', reelId);
    return res.json({ ok: true });
  }
  res.status(400).json({ error: 'Неизвестное действие' });
});

// ── GET /api/scores ──
app.get('/api/scores', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { data } = await supabase.from('users').select('scores').eq('id', me.id).single();
  res.json(data?.scores || {});
});

// ── POST /api/scores ──
app.post('/api/scores', async (req, res) => {
  const me = auth(req, res); if (!me) return;
  const game = req.query.game;
  const newScore = parseInt(req.query.score);
  if (!game || isNaN(newScore)) return res.status(400).json({ error: 'Нет данных' });
  const { data: user } = await supabase.from('users').select('scores').eq('id', me.id).single();
  const scores = user?.scores || {};
  if (!scores[game] || newScore > scores[game]) {
    scores[game] = newScore;
    await supabase.from('users').update({ scores }).eq('id', me.id);
  }
  res.json({ best: scores[game] });
});

// ── POST /api/typing ──
app.post('/api/typing', async (req, res) => {
  res.json({ ok: true });
});

// ── GET /api/typing ──
app.get('/api/typing', async (req, res) => {
  res.json({ typing: false });
});

// ── POST /api/heartbeat ──
app.post('/api/heartbeat', async (req, res) => {
  res.json({ ok: true });
});

// SPA fallback — все не-API маршруты отдают index.html
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const __dirname = dirname(fileURLToPath(import.meta.url));
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🌊 Волна запущена на порту ${PORT}`));
