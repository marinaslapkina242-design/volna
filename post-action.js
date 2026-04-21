import jwt from 'jsonwebtoken';
import { supabase, JWT_SECRET, cors, getToken } from './_db.js';

function auth(req) {
  const token = getToken(req);
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const user = auth(req);
  if (!user) return res.status(401).json({ error: 'Нет доступа' });

  const postId = parseInt(req.query.id);
  const action = req.query.action; // 'like' or 'comment'

  const { data: post } = await supabase
    .from('posts').select('*').eq('id', postId).single();
  if (!post) return res.status(404).json({ error: 'Пост не найден' });

  if (action === 'like') {
    let likes = post.likes || [];
    const idx = likes.indexOf(user.id);
    if (idx === -1) likes.push(user.id); else likes.splice(idx, 1);
    await supabase.from('posts').update({ likes }).eq('id', postId);
    return res.json({ likes });
  }

  if (action === 'comment') {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Текст пуст' });
    const comment = { userId: user.id, text: text.trim(), time: new Date().toISOString() };
    const comments = [...(post.comments || []), comment];
    await supabase.from('posts').update({ comments }).eq('id', postId);
    return res.json(comment);
  }

  res.status(400).json({ error: 'Неизвестное действие' });
}
