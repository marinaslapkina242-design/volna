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

  const user = auth(req);
  if (!user) return res.status(401).json({ error: 'Нет доступа' });

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, name, bio, joined, interests, banner_color, following')
      .eq('id', user.id)
      .single();
    if (error) return res.status(404).json({ error: 'Не найден' });
    return res.json(data);
  }

  if (req.method === 'PATCH') {
    const { name, bio, interests, banner_color } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (bio !== undefined) updates.bio = bio;
    if (interests !== undefined) updates.interests = interests;
    if (banner_color !== undefined) updates.banner_color = banner_color;

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', user.id)
      .select('id, username, name, bio, joined, interests, banner_color, following')
      .single();

    if (error) return res.status(500).json({ error: 'Ошибка' });
    return res.json(data);
  }

  res.status(405).end();
}
