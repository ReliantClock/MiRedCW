-- ============================================================
--  RedCW — Supabase Schema
--  Ejecutar en el SQL Editor de tu proyecto Supabase
-- ============================================================

-- Habilitar UUID
create extension if not exists "pgcrypto";

-- ── Perfiles ──────────────────────────────────────────────────
create table if not exists profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text not null,
  bio         text,
  avatar_url  text,
  banner_url  text,
  banner_color text default '#6C63FF',
  role        text not null default 'usuario'
              check (role in ('usuario','encargado','administrador','propietario')),
  plan        text not null default 'free'
              check (plan in ('free','n1','n2','n3')),
  plan_expires timestamptz,
  suspended   boolean default false,
  suspend_reason text,
  name_color  text,
  created_at  timestamptz default now()
);

-- Trigger: crear perfil automáticamente al registrarse
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ── Grupos de noticias ────────────────────────────────────────
create table if not exists news_groups (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_by uuid references profiles(id) on delete set null,
  created_at timestamptz default now()
);

-- ── Foros ─────────────────────────────────────────────────────
create table if not exists forums (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  is_private   boolean default false,
  is_anon      boolean default false,
  is_hidden    boolean default false,
  member_count integer default 1,
  created_by   uuid references profiles(id) on delete set null,
  created_at   timestamptz default now()
);

-- ── Miembros de foro ──────────────────────────────────────────
create table if not exists forum_members (
  id        uuid primary key default gen_random_uuid(),
  forum_id  uuid references forums(id) on delete cascade,
  user_id   uuid references profiles(id) on delete cascade,
  role      text default 'member' check (role in ('admin','member')),
  joined_at timestamptz default now(),
  unique (forum_id, user_id)
);

-- ── Publicaciones ─────────────────────────────────────────────
create table if not exists posts (
  id            uuid primary key default gen_random_uuid(),
  section       text not null check (section in ('inicio','noticias','forum')),
  news_group_id uuid references news_groups(id) on delete cascade,
  forum_id      uuid references forums(id) on delete cascade,
  user_id       uuid references profiles(id) on delete cascade,
  content       text not null,
  images        text[],
  is_anon       boolean default false,
  likes_count   integer default 0,
  comments_count integer default 0,
  post_color    text,   -- N3 plan feature
  created_at    timestamptz default now()
);

-- ── Comentarios ───────────────────────────────────────────────
create table if not exists comments (
  id         uuid primary key default gen_random_uuid(),
  post_id    uuid references posts(id) on delete cascade,
  user_id    uuid references profiles(id) on delete cascade,
  content    text not null,
  is_anon    boolean default false,
  created_at timestamptz default now()
);

-- ── Likes ─────────────────────────────────────────────────────
create table if not exists likes (
  id      uuid primary key default gen_random_uuid(),
  post_id uuid references posts(id) on delete cascade,
  user_id uuid references profiles(id) on delete cascade,
  unique (post_id, user_id)
);

-- Triggers: actualizar contadores
create or replace function update_likes_count()
returns trigger language plpgsql as $$
begin
  if tg_op = 'INSERT' then
    update posts set likes_count = likes_count + 1 where id = new.post_id;
  elsif tg_op = 'DELETE' then
    update posts set likes_count = greatest(likes_count - 1, 0) where id = old.post_id;
  end if;
  return null;
end;
$$;

drop trigger if exists on_like_change on likes;
create trigger on_like_change
  after insert or delete on likes
  for each row execute procedure update_likes_count();

create or replace function update_comments_count()
returns trigger language plpgsql as $$
begin
  if tg_op = 'INSERT' then
    update posts set comments_count = comments_count + 1 where id = new.post_id;
  elsif tg_op = 'DELETE' then
    update posts set comments_count = greatest(comments_count - 1, 0) where id = old.post_id;
  end if;
  return null;
end;
$$;

drop trigger if exists on_comment_change on comments;
create trigger on_comment_change
  after insert or delete on comments
  for each row execute procedure update_comments_count();

-- ── Lista blanca ──────────────────────────────────────────────
create table if not exists whitelist (
  id         uuid primary key default gen_random_uuid(),
  email      text unique not null,
  created_at timestamptz default now()
);

-- ── RLS (Row Level Security) ──────────────────────────────────

alter table profiles enable row level security;
alter table posts enable row level security;
alter table comments enable row level security;
alter table likes enable row level security;
alter table forums enable row level security;
alter table forum_members enable row level security;
alter table news_groups enable row level security;
alter table whitelist enable row level security;

-- Perfiles: todos pueden leer, solo el propio usuario puede editar
create policy "profiles_read" on profiles for select using (true);
create policy "profiles_update" on profiles for update using (auth.uid() = id);

-- Posts: leer todos; insertar autenticados; eliminar propio o admin
create policy "posts_read" on posts for select using (true);
create policy "posts_insert" on posts for insert with check (auth.uid() = user_id);
create policy "posts_delete" on posts for delete using (
  auth.uid() = user_id or
  exists (select 1 from profiles where id = auth.uid() and role in ('administrador','propietario'))
);

-- Comments
create policy "comments_read" on comments for select using (true);
create policy "comments_insert" on comments for insert with check (auth.uid() = user_id);
create policy "comments_delete" on comments for delete using (auth.uid() = user_id);

-- Likes
create policy "likes_read" on likes for select using (true);
create policy "likes_insert" on likes for insert with check (auth.uid() = user_id);
create policy "likes_delete" on likes for delete using (auth.uid() = user_id);

-- Forums
create policy "forums_read" on forums for select using (true);
create policy "forums_insert" on forums for insert with check (auth.uid() = created_by);
create policy "forums_update" on forums for update using (auth.uid() = created_by);

-- Forum members
create policy "members_read" on forum_members for select using (true);
create policy "members_insert" on forum_members for insert with check (auth.uid() = user_id);
create policy "members_delete" on forum_members for delete using (auth.uid() = user_id);

-- News groups: admins y propietarios
create policy "newsgroups_read" on news_groups for select using (true);
create policy "newsgroups_insert" on news_groups for insert with check (
  exists (select 1 from profiles where id = auth.uid() and role in ('administrador','propietario'))
);

-- Whitelist: solo propietario y admin
create policy "whitelist_read" on whitelist for select using (
  exists (select 1 from profiles where id = auth.uid() and role in ('administrador','propietario'))
);
create policy "whitelist_insert" on whitelist for insert with check (
  exists (select 1 from profiles where id = auth.uid() and role in ('administrador','propietario'))
);
create policy "whitelist_delete" on whitelist for delete using (
  exists (select 1 from profiles where id = auth.uid() and role in ('administrador','propietario'))
);

-- ── Storage buckets ───────────────────────────────────────────
-- Crear manualmente en Supabase Dashboard → Storage:
-- • "avatars"  → público
-- • "banners"  → público
-- • "posts"    → público
