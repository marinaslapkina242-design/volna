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

  // URL: /api/follow?id=123
  const targetId = parseInt(req.query.id);
  if (!targetId) return res.status(400).json({ error: 'Нет id' });

  const { data: me } = await supabase
    .from('users')
    .select('following')
    .eq('id', user.id)
    .single();

  let following = me.following || [];
  const idx = following.indexOf(targetId);
  if (idx === -1) following.push(targetId);
  else following.splice(idx, 1);

  await supabase.from('users').update({ following }).eq('id', user.id);
  res.json({ following });
}
