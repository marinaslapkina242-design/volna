import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const JWT_SECRET = process.env.JWT_SECRET || 'volna_dev_secret';

// ── CORS ──
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

// ── AUTH MIDDLEWARE ──
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
  const d = new Date(isoStr);
  const now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60) return 'только что';
  if (diff < 3600) return `${Math.floor(diff / 60)}м назад`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}ч назад`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}д назад`;
  return d.toLocaleDateString('ru');
}

function chatKey(a, b) { return [a, b].sort((x, y) => x - y).join('-'); }

// ══════════════════════════════════════
// ГЛАВНЫЙ ОБРАБОТЧИК
// ══════════════════════════════════════
export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const url = req.url.split('?')[0].replace(/^\/api/, '');
  const method = req.method;
  const query = req.query;
  const body = req.body || {};

  // ── POST /api/register ──
  if (url === '/register' && method === 'POST') {
    const { username, name, password } = body;
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
    return res.json({ token, user: safeUser(user) });
  }

  // ── POST /api/login ──
  if (url === '/login' && method === 'POST') {
    const { username, password } = body;
    const { data: user } = await supabase
      .from('users').select('*').eq('username', username).single();
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token, user: safeUser(user) });
  }

  // ── Всё ниже требует авторизации ──
  const authUser = getUser(req);
  if (!authUser && url !== '/register' && url !== '/login')
    return res.status(401).json({ error: 'Нет доступа' });

  // ── GET /api/me ──
  if (url === '/me' && method === 'GET') {
    const { data } = await supabase
      .from('users')
      .select('id, username, name, bio, joined, interests, banner_color, following')
      .eq('id', authUser.id).single();
    return res.json(data);
  }

  // ── PATCH /api/me ──
  if (url === '/me' && method === 'PATCH') {
    const { name, bio, interests, banner_color } = body;
    const updates = {};
    if (name) updates.name = name;
    if (bio !== undefined) updates.bio = bio;
    if (interests !== undefined) updates.interests = interests;
    if (banner_color !== undefined) updates.banner_color = banner_color;
    const { data } = await supabase
      .from('users').update(updates).eq('id', authUser.id)
      .select('id, username, name, bio, joined, interests, banner_color, following').single();
    return res.json(data);
  }

  // ── GET /api/users ──
  if (url === '/users' && method === 'GET') {
    const { data } = await supabase
      .from('users').select('id, username, name, bio, following');
    return res.json(data || []);
  }

  // ── POST /api/follow?id=X ──
  if (url === '/follow' && method === 'POST') {
    const targetId = parseInt(query.id);
    const { data: me } = await supabase
      .from('users').select('following').eq('id', authUser.id).single();
    let following = me.following || [];
    const idx = following.indexOf(targetId);
    if (idx === -1) following.push(targetId); else following.splice(idx, 1);
    await supabase.from('users').update({ following }).eq('id', authUser.id);
    return res.json({ following });
  }

  // ── GET /api/posts ── лента или посты пользователя
  if (url === '/posts' && method === 'GET') {
    if (query.userId) {
      const { data } = await supabase
        .from('posts').select('*').eq('user_id', parseInt(query.userId))
        .order('created_at', { ascending: false });
      return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
    }
    const { data: me } = await supabase
      .from('users').select('following').eq('id', authUser.id).single();
    const ids = [authUser.id, ...(me.following || [])];
    const { data } = await supabase
      .from('posts').select('*').in('user_id', ids)
      .order('created_at', { ascending: false });
    return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
  }

  // ── POST /api/posts ── создать пост
  if (url === '/posts' && method === 'POST') {
    const { text } = body;
    if (!text?.trim()) return res.status(400).json({ error: 'Текст пуст' });
    const { data, error } = await supabase
      .from('posts')
      .insert({ user_id: authUser.id, text: text.trim(), likes: [], comments: [] })
      .select().single();
    if (error) return res.status(500).json({ error: 'Ошибка' });
    return res.json({ ...data, timeFormatted: 'только что' });
  }

  // ── POST /api/post-action?id=X&action=like|comment ──
  if (url === '/post-action' && method === 'POST') {
    const postId = parseInt(query.id);
    const action = query.action;
    const { data: post } = await supabase
      .from('posts').select('*').eq('id', postId).single();
    if (!post) return res.status(404).json({ error: 'Пост не найден' });

    if (action === 'like') {
      let likes = post.likes || [];
      const idx = likes.indexOf(authUser.id);
      if (idx === -1) likes.push(authUser.id); else likes.splice(idx, 1);
      await supabase.from('posts').update({ likes }).eq('id', postId);
      return res.json({ likes });
    }
    if (action === 'comment') {
      const { text } = body;
      if (!text?.trim()) return res.status(400).json({ error: 'Текст пуст' });
      const comment = { userId: authUser.id, text: text.trim(), time: new Date().toISOString() };
      const comments = [...(post.comments || []), comment];
      await supabase.from('posts').update({ comments }).eq('id', postId);
      return res.json(comment);
    }
    return res.status(400).json({ error: 'Неизвестное действие' });
  }

  // ── GET /api/messages ── список чатов
  if (url === '/messages' && method === 'GET' && !query.userId) {
    const { data: rows } = await supabase
      .from('messages')
      .select('*')
      .or(`user1_id.eq.${authUser.id},user2_id.eq.${authUser.id}`);
    const convos = await Promise.all((rows || []).map(async row => {
      const otherId = row.user1_id === authUser.id ? row.user2_id : row.user1_id;
      const { data: other } = await supabase
        .from('users').select('id, name, username').eq('id', otherId).single();
      const msgs = row.messages || [];
      const last = msgs.length ? msgs[msgs.length - 1] : null;
      return { userId: otherId, name: other?.name || '', username: other?.username || '', lastMessage: last?.text || '', lastTime: last?.time || '' };
    }));
    return res.json(convos);
  }

  // ── GET /api/messages?userId=X ── получить чат
  if (url === '/messages' && method === 'GET' && query.userId) {
    const otherId = parseInt(query.userId);
    const key = chatKey(authUser.id, otherId);
    const { data: row } = await supabase
      .from('messages').select('messages').eq('chat_key', key).single();
    const msgs = (row?.messages || []).map(m => ({
      ...m,
      timeFormatted: new Date(m.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    }));
    return res.json(msgs);
  }

  // ── POST /api/messages?userId=X ── отправить сообщение
  if (url === '/messages' && method === 'POST' && query.userId) {
    const otherId = parseInt(query.userId);
    const { text } = body;
    if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
    const key = chatKey(authUser.id, otherId);
    const { data: existing } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();
    const newMsg = { from: authUser.id, text: text.trim(), time: new Date().toISOString() };
    if (existing) {
      await supabase.from('messages').update({ messages: [...(existing.messages || []), newMsg] }).eq('chat_key', key);
    } else {
      const [u1, u2] = key.split('-').map(Number);
      await supabase.from('messages').insert({ chat_key: key, user1_id: u1, user2_id: u2, messages: [newMsg] });
    }
    return res.json({ ...newMsg, timeFormatted: new Date(newMsg.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' }) });
  }

  return res.status(404).json({ error: 'Не найдено' });
}
