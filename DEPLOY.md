# 🌊 Деплой Волны на Vercel

## Структура файлов

```
volna/
├── index.html          ← фронтенд (переписан с API)
├── vercel.json         ← конфиг Vercel
├── package.json        ← зависимости
├── supabase_schema.sql ← схема БД (запустить в Supabase)
└── api/
    ├── _db.js          ← общие утилиты
    ├── register.js     ← POST /api/register
    ├── login.js        ← POST /api/login
    ├── me.js           ← GET/PATCH /api/me
    ├── users.js        ← GET /api/users
    ├── follow.js       ← POST /api/follow?id=X
    ├── posts.js        ← GET/POST /api/posts
    ├── post-action.js  ← POST /api/post-action?id=X&action=like|comment
    └── messages.js     ← GET/POST /api/messages
```

---

## Шаг 1 — Создать БД в Supabase (бесплатно)

1. Зайди на https://supabase.com → **New project**
2. Придумай название и пароль БД → **Create new project**
3. Подожди ~1 минуту пока создаётся
4. Иди в **SQL Editor** (левая панель)
5. Вставь содержимое файла `supabase_schema.sql` → **Run**
6. Иди в **Settings → API**
7. Скопируй:
   - **Project URL** → это `SUPABASE_URL`
   - **service_role** (Secret) → это `SUPABASE_SERVICE_KEY`

---

## Шаг 2 — Залить проект на GitHub

1. Создай новый репозиторий на https://github.com
2. Загрузи туда папку `volna/` (все файлы включая папку `api/`)

---

## Шаг 3 — Деплой на Vercel

1. Зайди на https://vercel.com → **Add New Project**
2. Подключи GitHub и выбери репозиторий
3. **Не меняй** настройки фреймворка (оставь "Other")
4. Раскрой **Environment Variables** и добавь три переменные:

   | Name | Value |
   |------|-------|
   | `SUPABASE_URL` | https://xxxx.supabase.co |
   | `SUPABASE_SERVICE_KEY` | eyJhbGciOiJIUzI1NiIs... |
   | `JWT_SECRET` | придумай длинную случайную строку |

5. Нажми **Deploy** → готово!

---

## Проверка

После деплоя открой `https://твой-проект.vercel.app` — увидишь экран входа Волны.

Зарегистрируй тестового пользователя — аккаунт сохранится в Supabase.

---

## Локальная разработка

```bash
npm install -g vercel
vercel dev
```

Создай файл `.env.local`:
```
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJ...
JWT_SECRET=local_dev_secret
```
