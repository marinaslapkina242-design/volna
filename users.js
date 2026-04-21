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

  // GET /api/users — all users
  if (req.method === 'GET') {
    const { data } = await supabase
      .from('users')
      .select('id, username, name, bio, following');
    return res.json(data || []);
  }

  res.status(405).end();
}
