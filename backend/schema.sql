-- PhishGuard AI: Supabase schema. Paste into the Supabase SQL editor and run.
create extension if not exists pgcrypto;

-- Crowdsourced threat reports ---------------------------------------------------
create table if not exists threat_reports (
  id            uuid primary key default gen_random_uuid(),
  url           text not null unique,                 -- normalized, scheme stripped
  domain        text not null,                        -- registered domain (evil.xyz)
  threat_type   text not null default 'Credential phishing',
  report_count  int  not null default 0,
  status        text not null default 'Pending',      -- Pending | Monitoring | Active | Takedown filed
  created_at    timestamptz not null default now(),
  last_reported timestamptz not null default now()
);
create index if not exists threat_reports_domain_idx on threat_reports(domain);

-- One upvote per (report, hashed reporter): a single client cannot inflate counts.
create table if not exists community_upvotes (
  report_id     uuid not null references threat_reports(id) on delete cascade,
  reporter_hash text not null,
  created_at    timestamptz not null default now(),
  primary key (report_id, reporter_hash)
);

-- Download inspections -----------------------------------------------------------
create table if not exists downloads_log (
  id           bigserial primary key,
  filename     text, source_url text, hops int, final_domain text,
  risk         text, status text, score int,
  created_at   timestamptz not null default now()
);

-- Raw scan events (feeds system stats) ----------------------------------------------
create table if not exists scan_log (
  id bigserial primary key, kind text, score int, domain text,
  created_at timestamptz not null default now()
);

-- Atomic voting / reporting functions ----------------------------------------------
create or replace function upvote_report(p_id uuid, p_reporter text)
returns threat_reports language plpgsql set search_path = public as $$
declare r threat_reports;
begin
  insert into community_upvotes(report_id, reporter_hash) values (p_id, p_reporter) on conflict do nothing;
  if found then
    update threat_reports set
      report_count  = report_count + 1,
      last_reported = now(),
      status = case when status = 'Takedown filed' then status
                    when report_count + 1 >= 25 then 'Active'
                    when report_count + 1 >= 3  then 'Monitoring'
                    else 'Pending' end
    where id = p_id;
  end if;
  select * into r from threat_reports where id = p_id;
  return r;
end $$;

create or replace function report_site(p_url text, p_domain text, p_type text, p_reporter text)
returns threat_reports language plpgsql set search_path = public as $$
declare rid uuid;
begin
  insert into threat_reports(url, domain, threat_type) values (p_url, p_domain, p_type)
    on conflict (url) do nothing;
  select id into rid from threat_reports where url = p_url;
  return upvote_report(rid, p_reporter);
end $$;

-- System stats ---------------------------------------------------------------------
create or replace view system_stats as
select (select count(*) from scan_log)                              as scans,
       (select count(*) from scan_log where score >= 60)            as blocked,
       (select coalesce(sum(report_count), 0) from threat_reports)  as reports,
       (select count(*) from downloads_log)                         as downloads;

-- Row Level Security ----------------------------------------------------------------
-- Enabled with NO public policies: the anon/authenticated roles can read/write nothing.
-- The backend uses the service_role key, which bypasses RLS.
alter table threat_reports   enable row level security;
alter table community_upvotes enable row level security;
alter table downloads_log    enable row level security;
alter table scan_log         enable row level security;
-- Optional: let the browser read the public ledger directly with the anon key.
-- create policy "public read threat_reports" on threat_reports for select to anon using (true);

-- Optional demo seed ---------------------------------------------------------------
insert into threat_reports(url, domain, threat_type, report_count, status) values
  ('paypa1-secure-login.xyz','paypa1-secure-login.xyz','Credential phishing',482,'Active'),
  ('amaz0n-refund.top','amaz0n-refund.top','Fake refund scam',311,'Active'),
  ('kyc-update-sbi.in.net','kyc-update-sbi.in.net','Bank KYC scam',207,'Active'),
  ('free-netfl1x-gift.com','free-netfl1x-gift.com','Giveaway scam',96,'Monitoring'),
  ('g00gle-docs-share.ru','g00gle-docs-share.ru','Malware delivery',58,'Takedown filed')
on conflict (url) do nothing;
