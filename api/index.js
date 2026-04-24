import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const JWT_SECRET = process.env.JWT_SECRET || 'volna_dev_secret';

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

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

  // ── Auth required below ──
  const authUser = getUser(req);
  if (!authUser) return res.status(401).json({ error: 'Нет доступа' });

  // ── GET /api/me ──
  if (url === '/me' && method === 'GET') {
    const { data } = await supabase
      .from('users')
      .select('id, username, name, bio, joined, interests, banner_color, following, avatar_url, avatar_base64, liked_tracks, playlist')
      .eq('id', authUser.id).single();
    return res.json(data);
  }

  // ── PATCH /api/me ──
  if (url === '/me' && method === 'PATCH') {
    const { name, bio, interests, banner_color, avatar_base64, avatar_url, liked_tracks, playlist } = body;
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
      .from('users').update(updates).eq('id', authUser.id)
      .select('id, username, name, bio, joined, interests, banner_color, following, avatar_url, avatar_base64, liked_tracks, playlist').single();
    return res.json(data);
  }

  // ── GET /api/users ──
  if (url === '/users' && method === 'GET') {
    const { data } = await supabase
      .from('users').select('id, username, name, bio, following, avatar_url, avatar_base64, banner_color, joined, interests');
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

  // ── GET /api/posts ──
  if (url === '/posts' && method === 'GET') {
    if (query.userId) {
      // all = все посты для вкладки "Все посты"
      if (query.userId === 'all') {
        const { data } = await supabase
          .from('posts').select('*')
          .order('created_at', { ascending: false })
          .limit(100);
        return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
      }
      const { data } = await supabase
        .from('posts').select('*').eq('user_id', parseInt(query.userId))
        .order('created_at', { ascending: false });
      return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
    }
    // лента подписок
    const { data: me } = await supabase
      .from('users').select('following').eq('id', authUser.id).single();
    const ids = [authUser.id, ...(me.following || [])];
    const { data } = await supabase
      .from('posts').select('*').in('user_id', ids)
      .order('created_at', { ascending: false });
    return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
  }

  // ── POST /api/posts ──
  if (url === '/posts' && method === 'POST') {
    const { text, image_url, image_base64 } = body;
    if (!text?.trim() && !image_url && !image_base64)
      return res.status(400).json({ error: 'Текст или фото обязательны' });
    const { data, error } = await supabase
      .from('posts')
      .insert({
        user_id: authUser.id,
        text: text?.trim() || '',
        likes: [],
        comments: [],
        image_url: image_url || null,
        image_base64: image_base64 || null
      })
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

  // ── POST /api/heartbeat ── обновить онлайн-статус
  if (url === '/heartbeat' && method === 'POST') {
    await supabase.from('presence').upsert({
      user_id: authUser.id,
      last_seen: new Date().toISOString()
    }, { onConflict: 'user_id' });
    return res.json({ ok: true });
  }

  // ── GET /api/online?ids=1,2,3 ── кто онлайн
  if (url === '/online' && method === 'GET') {
    const ids = (query.ids || '').split(',').map(Number).filter(Boolean);
    if (!ids.length) return res.json({});
    const since = new Date(Date.now() - 20000).toISOString(); // 20 секунд
    const { data } = await supabase
      .from('presence')
      .select('user_id, last_seen')
      .in('user_id', ids)
      .gte('last_seen', since);
    const result = {};
    (data || []).forEach(r => { result[r.user_id] = true; });
    return res.json(result);
  }

  // ── POST /api/typing?to=X ── я печатаю собеседнику X
  if (url === '/typing' && method === 'POST') {
    const toId = parseInt(query.to);
    await supabase.from('presence').upsert({
      user_id: authUser.id,
      last_seen: new Date().toISOString(),
      typing_to: toId,
      typing_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    return res.json({ ok: true });
  }

  // ── GET /api/typing?from=X ── печатает ли X мне?
  if (url === '/typing' && method === 'GET') {
    const fromId = parseInt(query.from);
    const since = new Date(Date.now() - 3500).toISOString();
    const { data } = await supabase
      .from('presence')
      .select('typing_to, typing_at')
      .eq('user_id', fromId)
      .single();
    const typing =
      data &&
      data.typing_to === authUser.id &&
      data.typing_at &&
      new Date(data.typing_at) > new Date(Date.now() - 3500);
    return res.json({ typing: !!typing });
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
      return {
        userId: otherId,
        name: other?.name || '',
        username: other?.username || '',
        lastMessage: last?.text || (last?.image_url || last?.image_base64 ? '📷 Фото' : ''),
        lastTime: last?.time || ''
      };
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
    const { text, image_base64 } = body;
    if (!text?.trim() && !image_base64)
      return res.status(400).json({ error: 'Пусто' });
    const key = chatKey(authUser.id, otherId);
    const { data: existing } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();
    const newMsg = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2,6),
      from: authUser.id,
      text: text?.trim() || '',
      image_base64: image_base64 || null,
      time: new Date().toISOString()
    };
    if (existing) {
      await supabase.from('messages')
        .update({ messages: [...(existing.messages || []), newMsg] })
        .eq('chat_key', key);
    } else {
      const [u1, u2] = key.split('-').map(Number);
      await supabase.from('messages')
        .insert({ chat_key: key, user1_id: u1, user2_id: u2, messages: [newMsg] });
    }
    return res.json({
      ...newMsg,
      timeFormatted: new Date(newMsg.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    });
  }

  // ── GET /api/reels ── лента видео
  if (url === '/reels' && method === 'GET') {
    const { data } = await supabase
      .from('reels')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);
    return res.json(data || []);
  }

  // ── POST /api/reels ── загрузить видео
  if (url === '/reels' && method === 'POST') {
    const { video_url, video_base64, caption } = body;
    if (!video_url && !video_base64) return res.status(400).json({ error: 'Видео обязательно' });
    const { data, error } = await supabase
      .from('reels')
      .insert({
        user_id: authUser.id,
        video_url: video_url || null,
        video_base64: video_base64 || null,
        caption: caption?.trim() || '',
        likes: [],
        views: 0
      })
      .select().single();
    if (error) return res.status(500).json({ error: 'Ошибка загрузки' });
    return res.json(data);
  }

  // ── POST /api/reels-action?id=X&action=like|view ──
  if (url === '/reels-action' && method === 'POST') {
    const reelId = parseInt(query.id);
    const action = query.action;
    const { data: reel } = await supabase
      .from('reels').select('*').eq('id', reelId).single();
    if (!reel) return res.status(404).json({ error: 'Не найдено' });
    if (action === 'like') {
      let likes = reel.likes || [];
      const idx = likes.indexOf(authUser.id);
      if (idx === -1) likes.push(authUser.id); else likes.splice(idx, 1);
      await supabase.from('reels').update({ likes }).eq('id', reelId);
      return res.json({ likes });
    }
    if (action === 'view') {
      await supabase.from('reels').update({ views: (reel.views || 0) + 1 }).eq('id', reelId);
      return res.json({ ok: true });
    }
    return res.status(400).json({ error: 'Неизвестное действие' });
  }

  // ── GET /api/scores ── получить рекорды текущего пользователя
  if (url === '/scores' && method === 'GET') {
    const { data } = await supabase
      .from('users').select('scores').eq('id', authUser.id).single();
    return res.json(data?.scores || {});
  }

  // ── POST /api/scores?game=snake&score=42 ── обновить рекорд
  if (url === '/scores' && method === 'POST') {
    const game = query.game;
    const newScore = parseInt(query.score);
    if (!game || isNaN(newScore)) return res.status(400).json({ error: 'Нет данных' });
    const { data: user } = await supabase
      .from('users').select('scores').eq('id', authUser.id).single();
    const scores = user?.scores || {};
    if (!scores[game] || newScore > scores[game]) {
      scores[game] = newScore;
      await supabase.from('users').update({ scores }).eq('id', authUser.id);
    }
    return res.json({ best: scores[game] });
  }

  // ── DELETE /api/messages?userId=X&msgId=Y ── удалить сообщение
  if (url === '/messages' && method === 'DELETE' && query.userId) {
    const otherId = parseInt(query.userId);
    const msgId = query.msgId;
    const key = chatKey(authUser.id, otherId);
    const { data: row } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();
    if (!row) return res.status(404).json({ error: 'Чат не найден' });
    const msgs = row.messages || [];
    // Ищем по id или по индексу
    const idx = msgId
      ? msgs.findIndex(m => m.id === msgId)
      : parseInt(query.msgIdx || '-1');
    if (idx === -1 || idx >= msgs.length) return res.status(404).json({ error: 'Сообщение не найдено' });
    if (msgs[idx].from !== authUser.id) return res.status(403).json({ error: 'Нельзя удалить чужое' });
    msgs[idx] = { ...msgs[idx], deleted: true, text: '', image_base64: null };
    await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
    return res.json({ ok: true });
  }

  // ── PATCH /api/messages?userId=X&msgId=Y ── редактировать сообщение
  if (url === '/messages' && method === 'PATCH' && query.userId) {
    const otherId = parseInt(query.userId);
    const msgId = query.msgId;
    const { text } = body;
    if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
    const key = chatKey(authUser.id, otherId);
    const { data: row } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();
    if (!row) return res.status(404).json({ error: 'Чат не найден' });
    const msgs = row.messages || [];
    const idx = msgId
      ? msgs.findIndex(m => m.id === msgId)
      : parseInt(query.msgIdx || '-1');
    if (idx === -1 || idx >= msgs.length) return res.status(404).json({ error: 'Сообщение не найдено' });
    if (msgs[idx].from !== authUser.id) return res.status(403).json({ error: 'Нельзя редактировать чужое' });
    msgs[idx] = { ...msgs[idx], text: text.trim(), edited: true };
    await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
    return res.json({ ok: true, text: text.trim() });
  }

  // ── POST /api/messages?userId=X&msgId=Y&action=react ── реакция
  if (url === '/messages' && method === 'POST' && query.userId && query.action === 'react') {
    const otherId = parseInt(query.userId);
    const msgId = query.msgId;
    const { emoji } = body;
    if (!emoji) return res.status(400).json({ error: 'Нет эмодзи' });
    const key = chatKey(authUser.id, otherId);
    const { data: row } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();
    if (!row) return res.status(404).json({ error: 'Чат не найден' });
    const msgs = row.messages || [];
    const idx = msgId
      ? msgs.findIndex(m => m.id === msgId)
      : parseInt(query.msgIdx || '-1');
    if (idx === -1 || idx >= msgs.length) return res.status(404).json({ error: 'Не найдено' });
    const reactions = msgs[idx].reactions || {};
    if (!reactions[emoji]) reactions[emoji] = [];
    const ui = reactions[emoji].indexOf(authUser.id);
    if (ui === -1) reactions[emoji].push(authUser.id);
    else reactions[emoji].splice(ui, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    msgs[idx] = { ...msgs[idx], reactions };
    await supabase.from('messages').update({ messages: msgs }).eq('chat_key', key);
    return res.json({ reactions });
  }

  return res.status(404).json({ error: 'Не найдено' });
}
