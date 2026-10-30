-- HANIL FIGHTER 계정 + 랭킹 (Supabase SQL Editor에 통째로 붙여넣고 Run)
create extension if not exists pgcrypto;

create table if not exists rank (
  k text primary key, nm text, elo int default 1000,
  w int default 0, l int default 0, d int default 0,
  ch jsonb default '{}', t bigint
);
create table if not exists account (
  k text primary key, nm text not null, pw text not null, tok uuid not null default gen_random_uuid(),
  created timestamptz default now()
);
create table if not exists report (
  mid text, k text, opp text, res real, ch int, out json, ts timestamptz default now(),
  primary key (mid, k)
);
alter table rank enable row level security;
alter table account enable row level security;
alter table report enable row level security;
drop policy if exists "insert" on rank;
drop policy if exists "update" on rank;
drop policy if exists "read" on rank;
create policy "read" on rank for select using (true);
-- 예전 테스트 기록(계정 없는 닉네임) 정리
delete from rank where k not in (select k from account);

create or replace function hf_register(p_nm text, p_pw text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_nm text := trim(p_nm); v_k text := lower(trim(p_nm)); v_t uuid;
begin
  if length(v_nm) < 1 or length(v_nm) > 10 then raise exception 'bad_name'; end if;
  if length(coalesce(p_pw,'')) < 4 then raise exception 'short_pw'; end if;
  if exists (select 1 from account a where a.k = v_k) then raise exception 'taken'; end if;
  insert into account (k, nm, pw) values (v_k, v_nm, crypt(p_pw, gen_salt('bf'))) returning tok into v_t;
  insert into rank (k, nm) values (v_k, v_nm) on conflict (k) do update set nm = excluded.nm;
  return json_build_object('nm', v_nm, 'tok', v_t);
end $$;

create or replace function hf_login(p_nm text, p_pw text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare a account;
begin
  select * into a from account where account.k = lower(trim(p_nm));
  if not found or a.pw <> crypt(coalesce(p_pw,''), a.pw) then raise exception 'bad_login'; end if;
  return json_build_object('nm', a.nm, 'tok', a.tok);
end $$;

-- 두 사람이 각자 결과를 보고하고, 서로 맞으면 Elo 반영
create or replace function hf_report(p_tok uuid, p_mid text, p_opp text, p_res real, p_ch int) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare a account; b account; o report; mine report; ra rank; rb rank;
  v_opp text := lower(trim(p_opp)); ea float; ka int; kb int; da int; db int; v_out json;
begin
  perform pg_advisory_xact_lock(hashtext(p_mid));
  select * into a from account where tok = p_tok;
  if not found then raise exception 'bad_tok'; end if;
  if v_opp = a.k then raise exception 'self'; end if;
  if p_res not in (0, 0.5, 1) then raise exception 'bad_res'; end if;
  insert into report (mid, k, opp, res, ch) values (p_mid, a.k, v_opp, p_res, p_ch) on conflict do nothing;
  select * into mine from report where mid = p_mid and k = a.k;
  if mine.out is not null then return mine.out; end if;
  select * into o from report where mid = p_mid and k = v_opp and opp = a.k;
  if not found then return null; end if;
  if abs(o.res + mine.res - 1) > 0.01 then raise exception 'mismatch'; end if;
  select * into b from account where k = o.k;
  if not found then raise exception 'bad_opp'; end if;
  insert into rank (k, nm) values (a.k, a.nm) on conflict (k) do nothing;
  insert into rank (k, nm) values (b.k, b.nm) on conflict (k) do nothing;
  select * into ra from rank where k = a.k;
  select * into rb from rank where k = b.k;
  ea := 1 / (1 + power(10, (rb.elo - ra.elo) / 400.0));
  ka := case when ra.w + ra.l + ra.d < 10 then 40 else 24 end;
  kb := case when rb.w + rb.l + rb.d < 10 then 40 else 24 end;
  da := round(ka * (mine.res - ea));
  db := round(kb * ((1 - mine.res) - (1 - ea)));
  update rank set elo = elo + da, nm = a.nm,
    w = w + (mine.res = 1)::int, l = l + (mine.res = 0)::int, d = d + (mine.res = 0.5)::int,
    ch = jsonb_set(coalesce(ch, '{}'), array[mine.ch::text], to_jsonb(coalesce((ch ->> mine.ch::text)::int, 0) + 1)),
    t = (extract(epoch from now()) * 1000)::bigint where k = a.k;
  update rank set elo = elo + db, nm = b.nm,
    w = w + (o.res = 1)::int, l = l + (o.res = 0)::int, d = d + (o.res = 0.5)::int,
    ch = jsonb_set(coalesce(ch, '{}'), array[o.ch::text], to_jsonb(coalesce((ch ->> o.ch::text)::int, 0) + 1)),
    t = (extract(epoch from now()) * 1000)::bigint where k = b.k;
  v_out := json_build_object('n', json_build_array(a.nm, b.nm), 'd', json_build_array(da, db),
                             'e', json_build_array(ra.elo + da, rb.elo + db));
  update report set out = v_out where mid = p_mid and k in (a.k, b.k);
  delete from report where ts < now() - interval '2 days';
  return v_out;
end $$;

create or replace function hf_poll(p_tok uuid, p_mid text) returns json
language sql security definer set search_path = public as $$
  select r.out from report r join account a on a.k = r.k where a.tok = p_tok and r.mid = p_mid;
$$;

grant execute on function hf_register(text,text), hf_login(text,text), hf_report(uuid,text,text,real,int), hf_poll(uuid,text) to anon, authenticated;
