import jwt from 'jsonwebtoken';
import { supabase, JWT_SECRET, cors, getToken } from './_db.js';

function auth(req) {
  const token = getToken(req);
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function chatKey(a, b) { return [a, b].sort((x, y) => x - y).join('-'); }

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const user = auth(req);
  if (!user) return res.status(401).json({ error: 'Нет доступа' });

  const otherId = req.query.userId ? parseInt(req.query.userId) : null;

  // GET /api/messages — list of conversations
  if (req.method === 'GET' && !otherId) {
    const { data: rows } = await supabase
      .from('messages')
      .select('*')
      .or(`user1_id.eq.${user.id},user2_id.eq.${user.id}`);

    const convos = await Promise.all((rows || []).map(async row => {
      const otherId = row.user1_id === user.id ? row.user2_id : row.user1_id;
      const { data: other } = await supabase
        .from('users').select('id, name, username').eq('id', otherId).single();
      const msgs = row.messages || [];
      const last = msgs.length ? msgs[msgs.length - 1] : null;
      return {
        userId: otherId,
        name: other?.name || '',
        username: other?.username || '',
        lastMessage: last?.text || '',
        lastTime: last?.time || ''
      };
    }));
    return res.json(convos);
  }

  // GET /api/messages?userId=X — get chat
  if (req.method === 'GET' && otherId) {
    const key = chatKey(user.id, otherId);
    const { data: row } = await supabase
      .from('messages').select('messages').eq('chat_key', key).single();

    const msgs = (row?.messages || []).map(m => ({
      ...m,
      timeFormatted: new Date(m.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    }));
    return res.json(msgs);
  }

  // POST /api/messages?userId=X — send message
  if (req.method === 'POST' && otherId) {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });

    const key = chatKey(user.id, otherId);
    const { data: existing } = await supabase
      .from('messages').select('*').eq('chat_key', key).single();

    const newMsg = { from: user.id, text: text.trim(), time: new Date().toISOString() };

    if (existing) {
      const updated = [...(existing.messages || []), newMsg];
      await supabase.from('messages').update({ messages: updated }).eq('chat_key', key);
    } else {
      const [u1, u2] = key.split('-').map(Number);
      await supabase.from('messages').insert({
        chat_key: key, user1_id: u1, user2_id: u2, messages: [newMsg]
      });
    }

    return res.json({
      ...newMsg,
      timeFormatted: new Date(newMsg.time).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    });
  }

  res.status(405).end();
}
