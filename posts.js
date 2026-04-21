import jwt from 'jsonwebtoken';
import { supabase, JWT_SECRET, cors, getToken } from './_db.js';

function auth(req) {
  const token = getToken(req);
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
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

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const user = auth(req);
  if (!user) return res.status(401).json({ error: 'Нет доступа' });

  // GET /api/posts — feed
  // GET /api/posts?userId=X — user posts
  if (req.method === 'GET') {
    const { userId } = req.query;

    if (userId) {
      const { data } = await supabase
        .from('posts')
        .select('*')
        .eq('user_id', parseInt(userId))
        .order('created_at', { ascending: false });
      return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
    }

    // Feed: my posts + following posts
    const { data: me } = await supabase
      .from('users').select('following').eq('id', user.id).single();
    const ids = [user.id, ...(me.following || [])];

    const { data } = await supabase
      .from('posts')
      .select('*')
      .in('user_id', ids)
      .order('created_at', { ascending: false });

    return res.json((data || []).map(p => ({ ...p, timeFormatted: formatTime(p.created_at) })));
  }

  // POST /api/posts — create
  if (req.method === 'POST') {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Текст пуст' });

    const { data, error } = await supabase
      .from('posts')
      .insert({ user_id: user.id, text: text.trim(), likes: [], comments: [] })
      .select()
      .single();

    if (error) return res.status(500).json({ error: 'Ошибка' });
    return res.json({ ...data, timeFormatted: 'только что' });
  }

  res.status(405).end();
}
