-- Запусти это в Supabase → SQL Editor

create table users (
  id         bigserial primary key,
  username   text unique not null,
  name       text not null,
  password_hash text not null,
  bio        text default '',
  joined     text default '',
  interests  text[] default '{}',
  banner_color int default 0,
  following  bigint[] default '{}'
);

create table posts (
  id         bigserial primary key,
  user_id    bigint references users(id),
  text       text not null,
  likes      bigint[] default '{}',
  comments   jsonb default '[]',
  created_at timestamptz default now()
);

create table messages (
  id        bigserial primary key,
  chat_key  text unique not null,
  user1_id  bigint references users(id),
  user2_id  bigint references users(id),
  messages  jsonb default '[]',
  updated_at timestamptz default now()
);
