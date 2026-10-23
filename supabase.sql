-- Ejecuta este script UNA VEZ en Supabase: SQL Editor > New query > Run

create table if not exists public.propinas_users (
  id uuid primary key default gen_random_uuid(),
  username text not null,
  username_lc text generated always as (lower(username)) stored unique,
  role text not null check (role in ('master', 'usuario')),
  salt text not null,
  hash text not null,
  created_at timestamptz not null default now()
);

-- Una sola fila con todos los datos de propinas (personal, quincenas, asistencia)
create table if not exists public.propinas_state (
  id int primary key default 1 check (id = 1),
  state jsonb not null default '{}'::jsonb,
  rev int not null default 0,
  updated_at timestamptz not null default now()
);
insert into public.propinas_state (id) values (1) on conflict do nothing;

-- Seguridad: RLS activado y sin políticas = la clave pública (anon) no puede leer ni escribir.
-- Solo el servidor, con la clave service_role, accede a estas tablas.
alter table public.propinas_users enable row level security;
alter table public.propinas_state enable row level security;

-- Guardado atómico del estado (incrementa la revisión sin carreras)
create or replace function public.propinas_save_state(p_state jsonb)
returns int
language sql
as $$
  update public.propinas_state
     set state = p_state, rev = rev + 1, updated_at = now()
   where id = 1
  returning rev;
$$;
revoke all on function public.propinas_save_state(jsonb) from public, anon, authenticated;
grant execute on function public.propinas_save_state(jsonb) to service_role;
