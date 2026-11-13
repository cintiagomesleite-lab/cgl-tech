-- =====================================================================
-- CGL Tech — NOTIFICAÇÕES CONTRATUAIS. Pode rodar mais de uma vez.
--  Tipos: PENDENCIAS (prazo para regularizar), ISENCAO (ressalva de responsabilidade),
--         SUSPENSAO (serviços suspensos) e RESCISAO (aviso prévio de 30 dias).
--  O texto fica CONGELADO na emissão, com número sequencial (ano/nº) e código de
--  verificação (SHA-256 do texto). Comprovação: e-mail com PDF, WhatsApp, Portal com
--  "Li e estou ciente" (data, hora e IP) e PDF para Correios/cartório.
-- =====================================================================
create table if not exists public.notificacoes (
  id             uuid primary key default gen_random_uuid(),
  escritorio_id  uuid not null references public.escritorios(id) on delete cascade,
  empresa_id     uuid not null,
  tipo           text not null check (tipo in ('PENDENCIAS','ISENCAO','SUSPENSAO','RESCISAO')),
  ano            integer not null,
  seq            integer not null,
  numero         text not null,
  titulo         text not null check (length(titulo) <= 300),
  texto          text not null check (length(texto) <= 30000),
  codigo         text not null,                       -- verificação (SHA-256 do texto)
  dados          jsonb not null default '{}'::jsonb,
  prazo_ate      date,
  efeito_em      date,
  destinatario   text,
  email_destino  text,
  telefone       text,
  portal_visivel boolean not null default true,
  status         text not null default 'EMITIDA' check (status in ('EMITIDA','CANCELADA')),
  emitida_por    uuid default auth.uid(),
  emitida_em     timestamptz not null default now(),
  email_status   text check (email_status in ('ENVIADO','ERRO')),
  email_erro     text,
  email_em       timestamptz,
  whatsapp_em    timestamptz,
  pdf_baixado_em timestamptz,
  ciente_em      timestamptz,
  ciente_por     uuid,
  ciente_nome    text,
  ciente_ip      text,
  cancelada_em   timestamptz,
  cancelada_motivo text,
  unique (escritorio_id, ano, seq),
  foreign key (empresa_id, escritorio_id) references public.empresas(id, escritorio_id) on delete cascade
);
create index if not exists notificacoes_empresa on public.notificacoes (empresa_id, emitida_em desc);
alter table public.notificacoes enable row level security;
drop policy if exists notificacoes_select on public.notificacoes;
create policy notificacoes_select on public.notificacoes for select to authenticated using (public.is_membro(escritorio_id));
revoke insert, update, delete on public.notificacoes from anon, authenticated;
grant select on public.notificacoes to authenticated;
drop trigger if exists trg_auditoria on public.notificacoes;
create trigger trg_auditoria after insert or update or delete on public.notificacoes
  for each row execute function public.fn_auditoria();

-- código de verificação (SHA-256), tolerante ao lugar onde o pgcrypto está instalado
create or replace function public.notificacao_codigo(p_texto text)
returns text language plpgsql immutable set search_path = public, extensions
as $$ begin return upper(encode(digest(convert_to(p_texto, 'UTF8'), 'sha256'), 'hex')); end; $$;

-- emitir (o texto não pode mais ser alterado depois)
create or replace function public.notificacao_emitir(
  p_empresa uuid, p_tipo text, p_titulo text, p_texto text, p_dados jsonb,
  p_prazo_ate date, p_efeito_em date, p_portal boolean)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_esc uuid; v_ano int := extract(year from (now() at time zone 'America/Sao_Paulo')); v_seq int; v_id uuid; v_num text; r record;
begin
  select e.escritorio_id into v_esc from public.empresas e where e.id = p_empresa;
  if v_esc is null or not public.is_membro(v_esc) then raise exception 'SEM_PERMISSAO'; end if;
  if p_tipo not in ('PENDENCIAS','ISENCAO','SUSPENSAO','RESCISAO') then raise exception 'Tipo inválido.'; end if;
  if length(coalesce(p_texto, '')) < 50 then raise exception 'Texto da notificação muito curto.'; end if;
  perform pg_advisory_xact_lock(hashtext('notif:' || v_esc::text || ':' || v_ano));
  select coalesce(max(seq), 0) + 1 into v_seq from public.notificacoes where escritorio_id = v_esc and ano = v_ano;
  v_num := v_ano || '/' || lpad(v_seq::text, 3, '0');
  select coalesce(nullif(e.contato_nome, ''), cl.nome) as nome, nullif(trim(cl.email), '') as email,
         nullif(coalesce(nullif(e.contato_telefone, ''), cl.telefone), '') as tel
    into r from public.empresas e join public.clientes cl on cl.id = e.cliente_id where e.id = p_empresa;
  insert into public.notificacoes (escritorio_id, empresa_id, tipo, ano, seq, numero, titulo, texto, codigo, dados,
                                   prazo_ate, efeito_em, destinatario, email_destino, telefone, portal_visivel)
  values (v_esc, p_empresa, p_tipo, v_ano, v_seq, v_num, left(p_titulo, 300), replace(p_texto, '{{NUMERO}}', v_num),
          public.notificacao_codigo(replace(p_texto, '{{NUMERO}}', v_num)), coalesce(p_dados, '{}'::jsonb),
          p_prazo_ate, p_efeito_em, r.nome, r.email, r.tel, coalesce(p_portal, true))
  returning id into v_id;
  return jsonb_build_object('id', v_id, 'numero', v_num);
end;
$$;
revoke all on function public.notificacao_emitir(uuid, text, text, text, jsonb, date, date, boolean) from public, anon;
grant execute on function public.notificacao_emitir(uuid, text, text, text, jsonb, date, date, boolean) to authenticated;

-- registrar WhatsApp / PDF baixado / cancelar
create or replace function public.notificacao_marcar(p_id uuid, p_acao text, p_motivo text default null)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_esc uuid;
begin
  select escritorio_id into v_esc from public.notificacoes where id = p_id;
  if v_esc is null or not public.is_membro(v_esc) then raise exception 'SEM_PERMISSAO'; end if;
  if p_acao = 'WHATSAPP' then update public.notificacoes set whatsapp_em = now() where id = p_id;
  elsif p_acao = 'PDF' then update public.notificacoes set pdf_baixado_em = coalesce(pdf_baixado_em, now()) where id = p_id;
  elsif p_acao = 'CANCELAR' then
    if not public.is_admin(v_esc) then raise exception 'SEM_PERMISSAO'; end if;
    update public.notificacoes set status = 'CANCELADA', cancelada_em = now(), cancelada_motivo = left(p_motivo, 500) where id = p_id;
  else raise exception 'Ação inválida.'; end if;
end;
$$;
revoke all on function public.notificacao_marcar(uuid, text, text) from public, anon;
grant execute on function public.notificacao_marcar(uuid, text, text) to authenticated;

-- Portal: o cliente registra "Li e estou ciente" (data, hora, IP e nome digitado)
create or replace function public.portal_dar_ciencia(p_id uuid, p_nome text)
returns timestamptz language plpgsql security definer set search_path = ''
as $$
declare v_ip text; v_quando timestamptz;
begin
  if length(trim(coalesce(p_nome, ''))) < 3 then raise exception 'Digite seu nome completo.'; end if;
  begin
    v_ip := split_part(coalesce(current_setting('request.headers', true)::json->>'x-forwarded-for', ''), ',', 1);
  exception when others then v_ip := null; end;
  update public.notificacoes n set ciente_em = now(), ciente_por = (select auth.uid()), ciente_nome = left(trim(p_nome), 200), ciente_ip = nullif(trim(v_ip), '')
   where n.id = p_id and n.status = 'EMITIDA' and n.portal_visivel and n.ciente_em is null
     and n.empresa_id in (select pe.empresa_id from public.portal_empresas_do_usuario() pe)
  returning ciente_em into v_quando;
  if v_quando is null then raise exception 'Notificação não encontrada ou já confirmada.'; end if;
  return v_quando;
end;
$$;
revoke all on function public.portal_dar_ciencia(uuid, text) from public, anon;
grant execute on function public.portal_dar_ciencia(uuid, text) to authenticated;

-- Portal do Cliente: mostra as notificações (com o botão de ciência)
create or replace function public.portal_dados()
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_esc uuid;
  v_out jsonb;
begin
  if v_uid is null then raise exception 'Faça login.'; end if;
  select pa.escritorio_id into v_esc from public.portal_acessos pa where pa.user_id = v_uid and pa.ativo limit 1;
  if v_esc is null then raise exception 'Este login não tem acesso ao portal. Fale com o escritório.'; end if;

  update public.portal_acessos set ultimo_acesso = now() where user_id = v_uid and ativo;

  with emp as (select empresa_id from public.portal_empresas_do_usuario() where escritorio_id = v_esc)
  select jsonb_build_object(
    'escritorio', (select jsonb_build_object('id', e.id, 'logo', e.logo, 'nome', e.nome, 'cnpj', e.cnpj, 'crc', e.crc, 'endereco', e.endereco, 'municipio', e.municipio, 'uf', e.uf,
                    'telefone', e.telefone, 'email', e.email, 'site', e.site, 'pix', e.pix, 'responsavel_nome', e.responsavel_nome, 'responsavel_crc', e.responsavel_crc)
                   from public.escritorios e where e.id = v_esc),
    'clientes', coalesce((select jsonb_agg(jsonb_build_object('nome', c.nome) order by c.nome)
                   from public.clientes c join public.portal_acessos pa on pa.cliente_id = c.id
                   where pa.user_id = v_uid and pa.ativo and c.escritorio_id = v_esc), '[]'::jsonb),
    'empresas', coalesce((select jsonb_agg(jsonb_build_object('id', e.id, 'razao_social', e.razao_social, 'nome_fantasia', e.nome_fantasia, 'cnpj', e.cnpj,
                    'regime', e.regime_tributario, 'status', e.status, 'servico_saude', coalesce((to_jsonb(e) ->> 'servico_saude')::boolean, false)) order by e.razao_social)
                   from public.empresas e where e.id in (select empresa_id from emp)), '[]'::jsonb),
    'obrigacoes', coalesce((select jsonb_agg(jsonb_build_object('empresa_id', o.empresa_id, 'tipo', o.tipo, 'competencia', o.competencia,
                    'vencimento', o.vencimento, 'status', o.status) order by o.vencimento)
                   from public.obrigacoes o where o.empresa_id in (select empresa_id from emp)
                     and o.vencimento between current_date - 60 and current_date + 75), '[]'::jsonb),
    'apuracoes', coalesce((select jsonb_agg(jsonb_build_object('empresa_id', a.empresa_id, 'competencia', a.competencia,
                    'das', coalesce(a.das_declarado, nullif(a.das_calculado, 0)), 'guia_enviada_em', a.detalhe -> 'guia' ->> 'enviadaEm') order by a.competencia desc)
                   from public.apuracoes a where a.empresa_id in (select empresa_id from emp)
                     and a.competencia >= (date_trunc('month', current_date) - interval '12 months')), '[]'::jsonb),
    'faturas', coalesce((select jsonb_agg(jsonb_build_object('id', f.id, 'empresa_id', f.empresa_id, 'mes_ref', f.mes_ref, 'ano_ref', f.ano_ref, 'valor', f.valor,
                    'vencimento', f.vencimento, 'status', f.status, 'data_pagamento', f.data_pagamento) order by f.vencimento desc)
                   from public.faturas f where f.empresa_id in (select empresa_id from emp) and f.status <> 'CANCELADA'
                     and f.vencimento >= current_date - 400), '[]'::jsonb),
    'documentos', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'empresa_id', d.empresa_id, 'titulo', d.titulo, 'categoria', d.categoria,
                    'validade', d.validade, 'arquivo_path', d.arquivo_path, 'criado_em', d.criado_em) order by d.criado_em desc)
                   from public.documentos d where d.visivel_cliente and d.arquivo_path is not null and d.empresa_id in (select empresa_id from emp)), '[]'::jsonb),
    'pendencias', coalesce((select jsonb_agg(jsonb_build_object('empresa_id', p.empresa_id, 'titulo', p.titulo, 'tipo', p.tipo,
                    'prioridade', p.prioridade, 'criado_em', p.criado_em) order by p.criado_em)
                   from public.pendencias p where not p.resolvida and p.empresa_id in (select empresa_id from emp)), '[]'::jsonb),
    'envios', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'empresa_id', x.empresa_id, 'categoria', x.categoria, 'competencia', x.competencia,
                    'nome_arquivo', x.nome_arquivo, 'arquivo_path', x.arquivo_path, 'status', x.status, 'criado_em', x.criado_em) order by x.criado_em desc)
                   from (select * from public.envios_cliente ec where ec.empresa_id in (select empresa_id from emp)
                          and ec.criado_em >= now() - interval '6 months' order by ec.criado_em desc limit 100) x), '[]'::jsonb),
    'pedidos', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'empresa_id', x.empresa_id, 'tomador_nome', x.tomador_nome, 'tomador_doc', x.tomador_doc,
                    'valor', x.valor, 'descricao', x.descricao, 'status', x.status, 'resposta', x.resposta, 'numero_nota', x.numero_nota,
                    'arquivo_path', case when x.status = 'EMITIDA' then x.arquivo_path end, 'criado_em', x.criado_em, 'atendido_em', x.atendido_em) order by x.criado_em desc)
                   from (select * from public.pedidos_nota pn where pn.empresa_id in (select empresa_id from emp)
                          and pn.criado_em >= now() - interval '6 months' order by pn.criado_em desc limit 100) x), '[]'::jsonb),
    'docs_mes', coalesce((select jsonb_agg(jsonb_build_object('empresa_id', e.id,
                    'competencia', (date_trunc('month', (now() at time zone 'America/Sao_Paulo')) - interval '1 month')::date,
                    'dia_limite', (date_trunc('month', (now() at time zone 'America/Sao_Paulo'))::date + (coalesce(e.docs_dia, 10) - 1)),
                    'docs', (select jsonb_agg(jsonb_build_object('codigo', c, 'nome', public.cobranca_doc_nome(c),
                               'recebido', exists (select 1 from public.docs_recebidos r where r.empresa_id = e.id and r.codigo = c
                                                     and r.competencia = (date_trunc('month', (now() at time zone 'America/Sao_Paulo')) - interval '1 month')::date)))
                             from unnest(e.docs_mensais) c)) order by e.razao_social)
                   from public.empresas e where e.id in (select empresa_id from emp) and cardinality(e.docs_mensais) > 0), '[]'::jsonb),
    'notificacoes', coalesce((select jsonb_agg(jsonb_build_object('id', n.id, 'empresa_id', n.empresa_id, 'numero', n.numero, 'tipo', n.tipo,
                    'titulo', n.titulo, 'texto', n.texto, 'codigo', n.codigo, 'emitida_em', n.emitida_em, 'prazo_ate', n.prazo_ate,
                    'efeito_em', n.efeito_em, 'ciente_em', n.ciente_em, 'ciente_nome', n.ciente_nome) order by n.emitida_em desc)
                   from public.notificacoes n where n.empresa_id in (select empresa_id from emp) and n.status = 'EMITIDA' and n.portal_visivel
                     and n.emitida_em >= now() - interval '1 year'), '[]'::jsonb)
  ) into v_out;
  return v_out;
end;
$$;
revoke all on function public.portal_dados() from public, anon;
grant execute on function public.portal_dados() to authenticated;

notify pgrst, 'reload schema';
