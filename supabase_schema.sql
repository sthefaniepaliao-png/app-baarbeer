-- Baarbeer Félix - banco de dados inicial para Supabase
-- Execute no SQL Editor de um projeto NOVO. Nunca exponha a chave service_role no navegador.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'caixa' check (role in ('proprietaria','barbeiro','caixa')),
  permissions jsonb not null default '{"view_dashboard":false,"view_movements":false,"create_movement":false,"edit_movement":false,"delete_movement":false,"view_cash":false,"open_cash":false,"close_cash":false,"view_reports":false,"manage_users":false}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.movements (
  id uuid primary key default gen_random_uuid(),
  movement_date date not null,
  type text not null check (type in ('Entrada','Saída')),
  category text not null,
  description text not null,
  amount numeric(12,2) not null check (amount > 0),
  payment_method text not null check (payment_method in ('Dinheiro','Pix','Débito','Crédito','Transferência','Outro')),
  person text,
  notes text,
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists public.cash_sessions (
  id uuid primary key default gen_random_uuid(),
  cash_date date not null,
  opening_amount numeric(12,2) not null default 0 check (opening_amount >= 0),
  expected_amount numeric(12,2),
  counted_amount numeric(12,2),
  difference numeric(12,2),
  status text not null default 'aberto' check (status in ('aberto','fechado')),
  opened_by uuid not null references public.profiles(id),
  closed_by uuid references public.profiles(id),
  opened_at timestamptz not null default now(),
  closed_at timestamptz,
  closing_notes text,
  constraint one_cash_session_per_day unique (cash_date)
);

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  table_name text not null,
  record_id text,
  action text not null,
  changed_by uuid,
  changed_at timestamptz not null default now(),
  old_data jsonb,
  new_data jsonb
);

create or replace function public.is_baarbeer_owner()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'proprietaria'); $$;

create or replace function public.baarbeer_has_permission(permission_name text)
returns boolean language sql stable security definer set search_path = public
as $$
  select public.is_baarbeer_owner() or coalesce((select (p.permissions ->> permission_name)::boolean from public.profiles p where p.id = auth.uid()), false);
$$;

create or replace function public.create_baarbeer_profile()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', split_part(new.email, '@', 1)), 'caixa')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_baarbeer on auth.users;
create trigger on_auth_user_created_baarbeer
after insert on auth.users for each row execute procedure public.create_baarbeer_profile();

create or replace function public.log_baarbeer_movement_change()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.audit_log(table_name, record_id, action, changed_by, old_data, new_data)
  values ('movements', case when tg_op = 'DELETE' then old.id::text else new.id::text end, tg_op, auth.uid(), case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) else null end, case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) else null end);
  if tg_op = 'DELETE' then return old; else return new; end if;
end;
$$;
drop trigger if exists movements_audit_trigger on public.movements;
create trigger movements_audit_trigger after insert or update or delete on public.movements
for each row execute procedure public.log_baarbeer_movement_change();

alter table public.profiles enable row level security;
alter table public.movements enable row level security;
alter table public.cash_sessions enable row level security;
alter table public.audit_log enable row level security;

-- Profiles: cada pessoa lê o próprio perfil; proprietária lê/gerencia todos.
drop policy if exists profiles_select_self_or_owner on public.profiles;
create policy profiles_select_self_or_owner on public.profiles for select to authenticated
using (id = auth.uid() or public.is_baarbeer_owner());
drop policy if exists profiles_update_owner on public.profiles;
create policy profiles_update_owner on public.profiles for update to authenticated
using (public.is_baarbeer_owner()) with check (public.is_baarbeer_owner());

-- Os dados financeiros pertencem ao mesmo negócio; acesso condicionado às permissões.
drop policy if exists movements_select_permission on public.movements;
create policy movements_select_permission on public.movements for select to authenticated
using (public.baarbeer_has_permission('view_movements') or public.baarbeer_has_permission('view_dashboard') or public.baarbeer_has_permission('view_cash') or public.baarbeer_has_permission('view_reports'));
drop policy if exists movements_insert_permission on public.movements;
create policy movements_insert_permission on public.movements for insert to authenticated
with check (public.baarbeer_has_permission('create_movement') and created_by = auth.uid());
drop policy if exists movements_update_permission on public.movements;
create policy movements_update_permission on public.movements for update to authenticated
using (public.baarbeer_has_permission('edit_movement')) with check (public.baarbeer_has_permission('edit_movement'));
drop policy if exists movements_delete_permission on public.movements;
create policy movements_delete_permission on public.movements for delete to authenticated
using (public.baarbeer_has_permission('delete_movement'));

-- Caixa: permissões separadas para consultar, abrir e fechar.
drop policy if exists cash_select_permission on public.cash_sessions;
create policy cash_select_permission on public.cash_sessions for select to authenticated
using (public.baarbeer_has_permission('view_cash'));
drop policy if exists cash_insert_permission on public.cash_sessions;
create policy cash_insert_permission on public.cash_sessions for insert to authenticated
with check (public.baarbeer_has_permission('open_cash') and opened_by = auth.uid());
drop policy if exists cash_update_permission on public.cash_sessions;
create policy cash_update_permission on public.cash_sessions for update to authenticated
using (public.baarbeer_has_permission('close_cash')) with check (public.baarbeer_has_permission('close_cash'));

-- Auditoria restrita à proprietária.
drop policy if exists audit_select_owner on public.audit_log;
create policy audit_select_owner on public.audit_log for select to authenticated using (public.is_baarbeer_owner());
revoke all on public.audit_log from anon;
grant select on public.audit_log to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.movements to authenticated;
grant select, insert, update on public.cash_sessions to authenticated;

-- CONFIGURAÇÃO DA PROPRIETÁRIA:
-- 1) Crie o usuário inicial em Authentication > Users (Add user).
-- 2) Copie o UUID desse usuário e execute o comando abaixo, substituindo UUID_DA_PROPRIETARIA:
-- update public.profiles set role='proprietaria', permissions='{"view_dashboard":true,"view_movements":true,"create_movement":true,"edit_movement":true,"delete_movement":true,"view_cash":true,"open_cash":true,"close_cash":true,"view_reports":true,"manage_users":true}'::jsonb where id='UUID_DA_PROPRIETARIA';
-- Para usuários novos, o trigger cria um perfil caixa com todas as permissões desligadas.
