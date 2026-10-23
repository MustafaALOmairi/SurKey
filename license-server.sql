-- ============================================================
-- سيرفر تراخيص برامجك – Supabase
-- شغّله في مشروع Supabase مستقل خاص بك (ليس مشروع المدرسة)
-- SQL Editor ← New query ← الصق الملف كامل ← Run
-- ============================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- ---------- الجداول ----------
create table if not exists public.licenses (
  key          text primary key,
  product      text not null default 'school-duty',
  customer     text,                    -- اسم المدرسة أو العميل
  plan         text not null default 'lifetime' check (plan in ('yearly', 'lifetime')),
  max_devices  int  not null default 1 check (max_devices between 1 and 100),
  expires_on   date,                    -- null = مدى الحياة
  status       text not null default 'active' check (status in ('active', 'blocked')),
  note         text,
  created_at   timestamptz not null default now()
);

create table if not exists public.license_devices (
  license_key  text not null references public.licenses (key) on delete cascade,
  device_id    text not null,
  device_name  text,
  activated_at timestamptz not null default now(),
  last_seen    timestamptz not null default now(),
  checks       int not null default 1,
  primary key (license_key, device_id)
);

-- محاولات التفعيل: لمعرفة من يحاول، ولتحديد عدد المحاولات
create table if not exists public.activation_log (
  id        bigserial primary key,
  key_tried text,
  device_id text,
  result    text,
  at        timestamptz not null default now()
);
create index if not exists activation_log_at_idx on public.activation_log (at desc);

-- حسابك أنت (لوحة إصدار المفاتيح)
create table if not exists public.owner_account (
  id            int primary key default 1 check (id = 1),
  username      text not null,
  password_hash text not null
);

create table if not exists public.owner_sessions (
  token      text primary key,
  expires_at timestamptz not null
);

-- ---------- توليد المفاتيح ----------
-- أبجدية بلا حروف متشابهة (0 O 1 I) لتفادي الخطأ عند الكتابة
create or replace function public.gen_license_key(p_prefix text default 'SD')
returns text language plpgsql set search_path = public, extensions as $$
declare
  alphabet text := '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  k text; g text; i int; j int;
begin
  loop
    k := upper(p_prefix);
    for j in 1..4 loop
      g := '';
      for i in 1..4 loop
        g := g || substr(alphabet, 1 + (get_byte(gen_random_bytes(1), 0) % length(alphabet)), 1);
      end loop;
      k := k || '-' || g;
    end loop;
    exit when not exists (select 1 from public.licenses where key = k);
  end loop;
  return k;
end $$;

-- ---------- التفعيل والتحقق (يناديها البرنامج) ----------
-- ترجع: {ok, reason, plan, expires_on, customer, devices_used, max_devices}
create or replace function public.license_activate(p_key text, p_device text, p_device_name text default null)
returns json language plpgsql security definer set search_path = public as $$
declare
  l public.licenses;
  used int;
  known boolean;
  res text;
begin
  p_key := upper(trim(coalesce(p_key, '')));
  p_device := trim(coalesce(p_device, ''));

  if length(p_device) < 8 then
    insert into public.activation_log (key_tried, device_id, result) values (p_key, p_device, 'bad_device');
    return json_build_object('ok', false, 'reason', 'bad_device');
  end if;

  -- حدّ المحاولات: 20 محاولة فاشلة من نفس الجهاز خلال ساعة
  if (select count(*) from public.activation_log
      where device_id = p_device and result <> 'ok' and at > now() - interval '1 hour') >= 20 then
    return json_build_object('ok', false, 'reason', 'too_many_tries');
  end if;

  select * into l from public.licenses where key = p_key;

  if l.key is null then res := 'not_found';
  elsif l.status = 'blocked' then res := 'blocked';
  elsif l.plan = 'yearly' and l.expires_on is not null and l.expires_on < current_date then res := 'expired';
  else
    select exists (select 1 from public.license_devices where license_key = l.key and device_id = p_device) into known;
    select count(*) into used from public.license_devices where license_key = l.key;
    if not known and used >= l.max_devices then res := 'device_limit';
    else res := 'ok';
    end if;
  end if;

  insert into public.activation_log (key_tried, device_id, result) values (p_key, p_device, res);

  if res <> 'ok' then
    perform pg_sleep(0.4);
    return json_build_object('ok', false, 'reason', res,
      'devices_used', (select count(*) from public.license_devices where license_key = p_key),
      'max_devices', l.max_devices);
  end if;

  insert into public.license_devices (license_key, device_id, device_name)
  values (l.key, p_device, left(coalesce(p_device_name, ''), 80))
  on conflict (license_key, device_id) do update
    set last_seen = now(), checks = public.license_devices.checks + 1,
        device_name = coalesce(nullif(excluded.device_name, ''), public.license_devices.device_name);

  return json_build_object('ok', true, 'reason', 'ok', 'plan', l.plan, 'customer', l.customer,
    'expires_on', l.expires_on, 'product', l.product,
    'devices_used', (select count(*) from public.license_devices where license_key = l.key),
    'max_devices', l.max_devices, 'server_time', now());
end $$;

-- تحقق دوري: لا يضيف جهازاً جديداً، فقط يتأكد أن الترخيص ما زال ساري
create or replace function public.license_check(p_key text, p_device text)
returns json language plpgsql security definer set search_path = public as $$
declare l public.licenses; ok boolean;
begin
  p_key := upper(trim(coalesce(p_key, '')));
  select * into l from public.licenses where key = p_key;
  if l.key is null then return json_build_object('ok', false, 'reason', 'not_found'); end if;
  if l.status = 'blocked' then return json_build_object('ok', false, 'reason', 'blocked'); end if;
  if l.plan = 'yearly' and l.expires_on is not null and l.expires_on < current_date then
    return json_build_object('ok', false, 'reason', 'expired', 'expires_on', l.expires_on);
  end if;
  select exists (select 1 from public.license_devices where license_key = l.key and device_id = p_device) into ok;
  if not ok then return json_build_object('ok', false, 'reason', 'device_removed'); end if;
  update public.license_devices set last_seen = now(), checks = checks + 1
   where license_key = l.key and device_id = p_device;
  return json_build_object('ok', true, 'reason', 'ok', 'plan', l.plan, 'customer', l.customer,
    'expires_on', l.expires_on, 'server_time', now());
end $$;

-- ---------- لوحتك: الدخول ----------
create or replace function public.owner_login(p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare a public.owner_account; t text;
begin
  select * into a from public.owner_account where id = 1;
  if a.username is null or lower(a.username) <> lower(trim(p_username))
     or a.password_hash <> crypt(p_password, a.password_hash) then
    perform pg_sleep(0.6);
    return null;
  end if;
  delete from public.owner_sessions where expires_at < now();
  t := encode(gen_random_bytes(32), 'hex');
  insert into public.owner_sessions (token, expires_at) values (t, now() + interval '14 days');
  return json_build_object('token', t, 'username', a.username);
end $$;

create or replace function public.owner_is_me() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.owner_sessions
                 where token = nullif(current_setting('request.headers', true)::json ->> 'x-owner', '')
                   and expires_at > now());
$$;

create or replace function public.owner_needs_setup() returns boolean
language sql security definer stable set search_path = public as $$
  select not exists (select 1 from public.owner_account);
$$;

create or replace function public.owner_setup(p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.owner_needs_setup() then raise exception 'already_setup'; end if;
  if length(trim(p_username)) < 3 then raise exception 'short_username'; end if;
  if length(p_password) < 8 then raise exception 'weak_password'; end if;
  insert into public.owner_account (id, username, password_hash)
  values (1, trim(p_username), crypt(p_password, gen_salt('bf', 10)));
  return public.owner_login(p_username, p_password);
end $$;

create or replace function public.owner_logout() returns void
language sql security definer set search_path = public as $$
  delete from public.owner_sessions where token = nullif(current_setting('request.headers', true)::json ->> 'x-owner', '');
$$;

create or replace function public.owner_change_password(p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  if length(p_password) < 8 then raise exception 'weak_password'; end if;
  update public.owner_account set password_hash = crypt(p_password, gen_salt('bf', 10)) where id = 1;
end $$;

-- ---------- لوحتك: إدارة المفاتيح ----------
create or replace function public.owner_new_license(
  p_customer text, p_plan text, p_max_devices int, p_months int default 12, p_note text default null)
returns json language plpgsql security definer set search_path = public as $$
declare k text;
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  if p_plan not in ('yearly', 'lifetime') then raise exception 'bad_plan'; end if;
  k := public.gen_license_key('SD');
  insert into public.licenses (key, customer, plan, max_devices, expires_on, note)
  values (k, nullif(trim(coalesce(p_customer, '')), ''), p_plan,
          greatest(1, least(100, coalesce(p_max_devices, 1))),
          case when p_plan = 'yearly' then current_date + (coalesce(p_months, 12) || ' months')::interval else null end,
          nullif(trim(coalesce(p_note, '')), ''));
  return json_build_object('key', k);
end $$;

create or replace function public.owner_list_licenses() returns json
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  return coalesce((
    select json_agg(x order by x.created_at desc) from (
      select l.key, l.customer, l.plan, l.max_devices, l.expires_on, l.status, l.note, l.created_at,
             (select count(*) from public.license_devices d where d.license_key = l.key) as devices_used,
             (select max(last_seen) from public.license_devices d where d.license_key = l.key) as last_seen,
             coalesce((select json_agg(json_build_object('device_id', d.device_id, 'name', d.device_name,
                       'activated_at', d.activated_at, 'last_seen', d.last_seen) order by d.activated_at)
                       from public.license_devices d where d.license_key = l.key), '[]'::json) as devices
      from public.licenses l) x), '[]'::json);
end $$;

create or replace function public.owner_set_status(p_key text, p_status text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  if p_status not in ('active', 'blocked') then raise exception 'bad_status'; end if;
  update public.licenses set status = p_status where key = upper(trim(p_key));
end $$;

create or replace function public.owner_extend(p_key text, p_months int) returns json
language plpgsql security definer set search_path = public as $$
declare d date;
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  update public.licenses
     set expires_on = greatest(coalesce(expires_on, current_date), current_date) + (p_months || ' months')::interval,
         plan = 'yearly'
   where key = upper(trim(p_key)) returning expires_on into d;
  return json_build_object('expires_on', d);
end $$;

create or replace function public.owner_make_lifetime(p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  update public.licenses set plan = 'lifetime', expires_on = null where key = upper(trim(p_key));
end $$;

create or replace function public.owner_set_devices(p_key text, p_max int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  update public.licenses set max_devices = greatest(1, least(100, p_max)) where key = upper(trim(p_key));
end $$;

-- تحرير جهاز: العميل غيّر الكمبيوتر
create or replace function public.owner_release_device(p_key text, p_device text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  delete from public.license_devices where license_key = upper(trim(p_key)) and device_id = p_device;
end $$;

create or replace function public.owner_delete_license(p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  delete from public.licenses where key = upper(trim(p_key));
end $$;

create or replace function public.owner_recent_activity(p_limit int default 60) returns json
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.owner_is_me() then raise exception 'not_allowed'; end if;
  return coalesce((select json_agg(x order by x.at desc) from (
    select key_tried, device_id, result, at from public.activation_log
    order by at desc limit greatest(1, least(300, p_limit))) x), '[]'::json);
end $$;

-- ---------- الحماية: لا أحد يقرأ الجداول مباشرة ----------
alter table public.licenses        enable row level security;
alter table public.license_devices enable row level security;
alter table public.activation_log  enable row level security;
alter table public.owner_account   enable row level security;
alter table public.owner_sessions  enable row level security;
revoke all on public.licenses, public.license_devices, public.activation_log,
               public.owner_account, public.owner_sessions from anon, authenticated;

-- البرنامج ولوحتك ينادون الدوال فقط
revoke execute on function public.gen_license_key(text) from public, anon, authenticated;
grant  execute on function public.license_activate(text, text, text) to anon, authenticated;
grant  execute on function public.license_check(text, text) to anon, authenticated;
grant  execute on function public.owner_login(text, text), public.owner_setup(text, text),
                           public.owner_needs_setup() to anon, authenticated;

-- ============================================================
-- بعد التشغيل: افتح لوحة المفاتيح وسجّل حسابك (أول مرة فقط)
-- ============================================================
