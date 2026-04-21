import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { supabase, JWT_SECRET, cors } from './_db.js';

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { username, name, password } = req.body;
  if (!username || !name || !password)
    return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Только латиница, цифры и _' });

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('username', username)
    .single();

  if (existing) return res.status(400).json({ error: 'Это имя уже занято' });

  const passwordHash = bcrypt.hashSync(password, 10);
  const now = new Date();
  const months = ['январь','февраль','март','апрель','май','июнь','июль','август','сентябрь','октябрь','ноябрь','декабрь'];
  const joined = months[now.getMonth()] + ' ' + now.getFullYear();

  const { data: user, error } = await supabase
    .from('users')
    .insert({ username, name, password_hash: passwordHash, bio: '', joined })
    .select()
    .single();

  if (error) return res.status(500).json({ error: 'Ошибка сервера' });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
}

function safeUser(u) {
  const { password_hash, ...safe } = u;
  return safe;
}
