require('dotenv').config();
const express  = require('express');
const path     = require('path');
const multer   = require('multer');
const bcrypt   = require('bcryptjs');
const { v4: uuid } = require('uuid');
const db       = require('./database');
const { gerarToken, requireAuth, requireAdmin } = require('./auth');
const mailer   = require('./mailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Upload ───────────────────────────────────────────────────h
const storage = multer.diskStorage({
  destination: path.join(__dirname, 'uploads'),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${uuid().slice(0,8)}${path.extname(file.originalname)}`),
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ─── Helpers ──────────────────────────────────────────────────
const SLA_HORAS = { Critica: 2, Alta: 4, Media: 24, Baixa: 72 };

function slaLimite(prioridade, base) {
  const h = SLA_HORAS[prioridade] || 24;
  const d = new Date(base || Date.now());
  d.setHours(d.getHours() + h);
  return d.toISOString().replace('T',' ').slice(0,19);
}

function agora() { return new Date().toISOString().replace('T',' ').slice(0,19); }

function gerarProtocolo() {
  const d = new Date();
  const dt = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
  return `OXI-${dt}-${String(Math.floor(Math.random()*9000)+1000)}`;
}

function notificar(usuario_id, tipo, titulo, mensagem, link='') {
  try {
    db.prepare('INSERT INTO notificacoes (usuario_id,tipo,titulo,mensagem,link) VALUES (?,?,?,?,?)')
      .run(usuario_id, tipo, titulo, mensagem, link);
  } catch {}
}

// ─── Middlewares ──────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname)));
app.use('/uploads', requireAuth, express.static(path.join(__dirname, 'uploads')));

// Rota raiz -> redireciona para login // trigger deploy
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

// ══════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });
  const u = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email.toLowerCase().trim());
  if (!u || !bcrypt.compareSync(senha, u.senha_hash))
    return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
  if (!u.ativo) return res.status(403).json({ erro: 'Usuário bloqueado. Contate o administrador.' });
  db.prepare('UPDATE usuarios SET ultimo_acesso = ? WHERE id = ?').run(agora(), u.id);
  const token = gerarToken(u);
  res.json({ token, usuario: { id:u.id, nome:u.nome, email:u.email, setor:u.setor, cargo:u.cargo, role:u.role } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id,nome,email,setor,cargo,role,ativo,criado_em,ultimo_acesso FROM usuarios WHERE id=?').get(req.usuario.id);
  res.json(u);
});

app.put('/api/auth/senha', requireAuth, (req, res) => {
  const { senha_atual, senha_nova } = req.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE id=?').get(req.usuario.id);
  if (!bcrypt.compareSync(senha_atual, u.senha_hash)) return res.status(400).json({ erro: 'Senha atual incorreta' });
  if (senha_nova.length < 6) return res.status(400).json({ erro: 'Nova senha deve ter pelo menos 6 caracteres' });
  db.prepare('UPDATE usuarios SET senha_hash=? WHERE id=?').run(bcrypt.hashSync(senha_nova, 10), u.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  USUÁRIOS (admin)
// ══════════════════════════════════════════════════════════════
app.get('/api/usuarios', requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id,nome,email,setor,cargo,role,ativo,criado_em,ultimo_acesso FROM usuarios ORDER BY nome').all());
});

app.post('/api/usuarios', requireAuth, requireAdmin, (req, res) => {
  const { nome, email, senha, setor, cargo, role } = req.body;
  if (!nome || !email || !senha || !setor) return res.status(400).json({ erro: 'Campos obrigatórios: nome, email, senha, setor' });
  if (db.prepare('SELECT id FROM usuarios WHERE email=?').get(email.toLowerCase()))
    return res.status(409).json({ erro: 'E-mail já cadastrado' });
  const r = db.prepare('INSERT INTO usuarios (nome,email,senha_hash,setor,cargo,role) VALUES (?,?,?,?,?,?)')
    .run(nome.trim(), email.toLowerCase().trim(), bcrypt.hashSync(senha, 10), setor, cargo||'', role||'usuario');
  res.status(201).json({ id: r.lastInsertRowid });
});

app.put('/api/usuarios/:id', requireAuth, requireAdmin, (req, res) => {
  const { nome, email, senha, setor, cargo, role, ativo } = req.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ erro: 'Usuário não encontrado' });
  const senhaHash = senha ? bcrypt.hashSync(senha, 10) : u.senha_hash;
  db.prepare('UPDATE usuarios SET nome=?,email=?,senha_hash=?,setor=?,cargo=?,role=?,ativo=? WHERE id=?')
    .run(nome||u.nome, (email||u.email).toLowerCase(), senhaHash, setor||u.setor, cargo??u.cargo, role||u.role, ativo??u.ativo, u.id);
  res.json({ ok: true });
});

app.delete('/api/usuarios/:id', requireAuth, requireAdmin, (req, res) => {
  if (parseInt(req.params.id) === req.usuario.id) return res.status(400).json({ erro: 'Não é possível remover a si mesmo' });
  db.prepare('UPDATE usuarios SET ativo=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  CHAMADOS
// ══════════════════════════════════════════════════════════════
app.get('/api/chamados', requireAuth, (req, res) => {
  const { status, prioridade, setor, categoria, responsavel, busca, periodo, atrasados } = req.query;
  let q = `SELECT c.*,
    u1.nome as solicitante_nome, u1.setor as solicitante_setor,
    u2.nome as responsavel_nome,
    (SELECT COUNT(*) FROM anexos WHERE chamado_id=c.id) as qtd_anexos,
    (SELECT nota FROM avaliacoes WHERE chamado_id=c.id) as avaliacao_nota
    FROM chamados c
    JOIN usuarios u1 ON c.solicitante_id=u1.id
    LEFT JOIN usuarios u2 ON c.responsavel_id=u2.id
    WHERE 1=1`;
  const p = [];
  if (req.usuario.role !== 'admin') { q += ' AND c.solicitante_id=?'; p.push(req.usuario.id); }
  if (status)      { q += ' AND c.status=?';     p.push(status); }
  if (prioridade)  { q += ' AND c.prioridade=?'; p.push(prioridade); }
  if (setor)       { q += ' AND c.setor=?';      p.push(setor); }
  if (categoria)   { q += ' AND c.categoria=?';  p.push(categoria); }
  if (responsavel) { q += ' AND c.responsavel_id=?'; p.push(responsavel); }
  if (busca)       { q += ' AND (c.titulo LIKE ? OR c.protocolo LIKE ? OR u1.nome LIKE ?)';
                     p.push(`%${busca}%`,`%${busca}%`,`%${busca}%`); }
  if (atrasados === '1') { q += ` AND c.status NOT IN ('Concluido','Cancelado') AND c.sla_limite < ?`; p.push(agora()); }
  if (periodo === 'hoje')   { q += " AND date(c.criado_em)=date('now','localtime')"; }
  if (periodo === 'semana') { q += " AND c.criado_em >= datetime('now','localtime','-7 days')"; }
  if (periodo === 'mes')    { q += " AND c.criado_em >= datetime('now','localtime','-30 days')"; }
  if (periodo === 'ano')    { q += " AND strftime('%Y',c.criado_em)=strftime('%Y',datetime('now','localtime'))"; }
  q += ' ORDER BY c.criado_em DESC';
  res.json(db.prepare(q).all(...p));
});

app.post('/api/chamados', requireAuth, (req, res) => {
  const { titulo, descricao, categoria, prioridade, observacoes } = req.body;
  if (!titulo||!descricao||!categoria) return res.status(400).json({ erro: 'Campos obrigatórios: titulo, descricao, categoria' });
  const u = db.prepare('SELECT * FROM usuarios WHERE id=?').get(req.usuario.id);
  const protocolo = gerarProtocolo();
  const sla = slaLimite(prioridade||'Media');
  const r = db.prepare(`INSERT INTO chamados (protocolo,titulo,descricao,categoria,prioridade,status,setor,solicitante_id,sla_limite)
    VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(protocolo,titulo,descricao,categoria,prioridade||'Media','Aberto',u.setor,u.id,sla);
  const cid = r.lastInsertRowid;
  db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
    .run(cid, u.id, u.nome, 'abertura', `Chamado aberto por ${u.nome} (${u.setor})`);
  const chamado = db.prepare('SELECT * FROM chamados WHERE id=?').get(cid);
  // Notificar admin
  const admins = db.prepare("SELECT id,email FROM usuarios WHERE role='admin' AND ativo=1").all();
  admins.forEach(a => {
    notificar(a.id,'novo_chamado',`Novo chamado: ${titulo}`,`Aberto por ${u.nome} — Prioridade: ${prioridade||'Media'}`,`/admin.html`);
    mailer.enviar({ para: a.email, assunto: `[${prioridade||'Media'}] Novo chamado: ${titulo}`, html: mailer.htmlNovoChamado(chamado, u.nome) });
  });
    mailer.enviar({ para: process.env.EMAIL_ADMIN, assunto: '[NOVO] ' + (prioridade||'Media') + ' - ' + titulo, html: mailer.htmlNovoChamado(chamado, u.nome) });
  res.status(201).json(chamado);
});

app.get('/api/chamados/:id', requireAuth, (req, res) => {
  const c = db.prepare(`SELECT c.*,u1.nome as solicitante_nome,u1.email as solicitante_email,u1.setor as solicitante_setor,
    u2.nome as responsavel_nome FROM chamados c
    JOIN usuarios u1 ON c.solicitante_id=u1.id LEFT JOIN usuarios u2 ON c.responsavel_id=u2.id
    WHERE c.id=?`).get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Não encontrado' });
  if (req.usuario.role!=='admin' && c.solicitante_id!==req.usuario.id)
    return res.status(403).json({ erro: 'Acesso negado' });
  const historico = db.prepare('SELECT * FROM historico_chamados WHERE chamado_id=? ORDER BY criado_em ASC').all(c.id);
  const anexos    = db.prepare('SELECT * FROM anexos WHERE chamado_id=? ORDER BY criado_em ASC').all(c.id);
  const avaliacao = db.prepare('SELECT * FROM avaliacoes WHERE chamado_id=?').get(c.id);
  res.json({ ...c, historico, anexos, avaliacao });
});

app.put('/api/chamados/:id', requireAuth, (req, res) => {
  const c = db.prepare('SELECT * FROM chamados WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Não encontrado' });
  if (req.usuario.role!=='admin' && c.solicitante_id!==req.usuario.id)
    return res.status(403).json({ erro: 'Acesso negado' });

  const now = agora();
  const mudancas = [];

  if (req.usuario.role==='admin') {
    const { status, prioridade, responsavel_id, comentario, sla_manual } = req.body;
    let fechado_em = c.fechado_em;
    let primeiro_atendimento_em = c.primeiro_atendimento_em;

    if (status && status !== c.status) {
      mudancas.push(`Status: "${c.status}" → "${status}"`);
      if (status==='Em Andamento' && !c.primeiro_atendimento_em) primeiro_atendimento_em = now;
      if (status==='Concluido'||status==='Cancelado') fechado_em = now;
    }
    if (prioridade && prioridade!==c.prioridade) mudancas.push(`Prioridade: "${c.prioridade}" → "${prioridade}"`);
    if (responsavel_id !== undefined) {
      const resp = responsavel_id ? db.prepare('SELECT nome FROM usuarios WHERE id=?').get(responsavel_id) : null;
      if (resp) mudancas.push(`Responsável: ${resp.nome}`);
    }
    if (comentario) mudancas.push(comentario);

    const novoSla = sla_manual ? sla_manual : (prioridade && prioridade!==c.prioridade ? slaLimite(prioridade, c.criado_em) : c.sla_limite);

    db.prepare(`UPDATE chamados SET status=?,prioridade=?,responsavel_id=?,sla_limite=?,
      primeiro_atendimento_em=?,fechado_em=?,atualizado_em=? WHERE id=?`)
      .run(status||c.status, prioridade||c.prioridade, responsavel_id??c.responsavel_id,
           novoSla, primeiro_atendimento_em, fechado_em, now, c.id);

    if (mudancas.length) {
      db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
        .run(c.id, req.usuario.id, req.usuario.nome, 'atualizacao', mudancas.join(' | '));
    }

    // Notificar solicitante
    const sol = db.prepare('SELECT * FROM usuarios WHERE id=?').get(c.solicitante_id);
    if (sol && mudancas.length) {
      notificar(sol.id, 'chamado_atualizado', `Chamado atualizado: ${c.titulo}`, mudancas.join('. '), '/app.html');
      const chamadoAtualizado = db.prepare('SELECT * FROM chamados WHERE id=?').get(c.id);
      const hist = { descricao: mudancas.join(' | ') };
      if (status==='Concluido') {
        mailer.enviar({ para: sol.email, assunto: `✅ Chamado concluído: ${c.titulo}`, html: mailer.htmlConcluido(chamadoAtualizado) });
      } else if (mudancas.length) {
        mailer.enviar({ para: sol.email, assunto: `Atualização: ${c.titulo}`, html: mailer.htmlAtualizacao(chamadoAtualizado, hist) });
      }
      mailer.enviar({ para: process.env.EMAIL_ADMIN, assunto: 'Atualizacao: ' + c.titulo, html: mailer.htmlAtualizacao(chamadoAtualizado, hist) });
    }
  } else {
    // Usuário: só pode adicionar observação
    const { observacao } = req.body;
    if (observacao) {
      db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
        .run(c.id, req.usuario.id, req.usuario.nome, 'observacao', `💬 ${observacao}`);
      db.prepare('UPDATE chamados SET atualizado_em=? WHERE id=?').run(now, c.id);
      // Notificar admin
      const admins = db.prepare("SELECT id,email FROM usuarios WHERE role='admin' AND ativo=1").all();
      admins.forEach(a => { notificar(a.id,'observacao','Obs em: '+c.titulo, req.usuario.nome+' adicionou uma observacao','/admin.html'); mailer.enviar({ para: a.email, assunto: 'Obs em: '+c.titulo, html: mailer.htmlNotifTecnico(c, req.usuario.nome, observacao) }); });
    }
  }
  const atualizado = db.prepare('SELECT * FROM chamados WHERE id=?').get(c.id);
  const historico = db.prepare('SELECT * FROM historico_chamados WHERE chamado_id=? ORDER BY criado_em ASC').all(c.id);
  const anexos = db.prepare('SELECT * FROM anexos WHERE chamado_id=?').all(c.id);
  const avaliacao = db.prepare('SELECT * FROM avaliacoes WHERE chamado_id=?').get(c.id);
  res.json({ ...atualizado, historico, anexos, avaliacao });
});

// ─── Upload de anexo ──────────────────────────────────────────
app.post('/api/chamados/:id/anexos', requireAuth, upload.single('arquivo'), (req, res) => {
  const c = db.prepare('SELECT * FROM chamados WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Chamado não encontrado' });
  if (req.usuario.role!=='admin' && c.solicitante_id!==req.usuario.id) return res.status(403).json({ erro: 'Acesso negado' });
  if (!req.file) return res.status(400).json({ erro: 'Nenhum arquivo enviado' });
  const r = db.prepare('INSERT INTO anexos (chamado_id,nome_original,nome_arquivo,tamanho,mime_type) VALUES (?,?,?,?,?)')
    .run(c.id, req.file.originalname, req.file.filename, req.file.size, req.file.mimetype);
  db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
    .run(c.id, req.usuario.id, req.usuario.nome, 'anexo', `📎 Anexo adicionado: ${req.file.originalname}`);
      const adm2 = db.prepare("SELECT id,email FROM usuarios WHERE role='admin' AND ativo=1").all();
        adm2.forEach(a => { notificar(a.id,'anexo','Anexo: '+c.titulo, req.usuario.nome+' adicionou um arquivo','/admin.html'); mailer.enviar({ para: a.email, assunto: 'Anexo: '+c.titulo, html: mailer.htmlNotifTecnico(c, req.usuario.nome, 'Arquivo: '+req.file.originalname) }); });
  res.json({ id: r.lastInsertRowid, nome_original: req.file.originalname, nome_arquivo: req.file.filename });
});

// ─── Avaliação ────────────────────────────────────────────────
app.post('/api/chamados/:id/avaliacao', requireAuth, (req, res) => {
  const c = db.prepare('SELECT * FROM chamados WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Não encontrado' });
  if (c.solicitante_id !== req.usuario.id) return res.status(403).json({ erro: 'Acesso negado' });
  if (c.status !== 'Concluido') return res.status(400).json({ erro: 'Só é possível avaliar chamados concluídos' });
  const { nota, comentario } = req.body;
  if (!nota || nota < 1 || nota > 5) return res.status(400).json({ erro: 'Nota deve ser entre 1 e 5' });
  const existe = db.prepare('SELECT id FROM avaliacoes WHERE chamado_id=?').get(c.id);
  if (existe) {
    db.prepare('UPDATE avaliacoes SET nota=?, comentario=? WHERE chamado_id=?')
      .run(nota, comentario||'', c.id);
    db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
      .run(c.id, req.usuario.id, req.usuario.nome, 'avaliacao', `⭐ Avaliação atualizada: ${nota}/5${comentario?` — "${comentario}"`:''}`)
  } else {
    db.prepare('INSERT INTO avaliacoes (chamado_id,usuario_id,nota,comentario) VALUES (?,?,?,?)')
      .run(c.id, req.usuario.id, nota, comentario||'');
    db.prepare('INSERT INTO historico_chamados (chamado_id,autor_id,autor_nome,tipo,descricao) VALUES (?,?,?,?,?)')
      .run(c.id, req.usuario.id, req.usuario.nome, 'avaliacao', `⭐ Avaliação: ${nota}/5${comentario?` — "${comentario}"`:''}`)
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  SUGESTÕES
// ══════════════════════════════════════════════════════════════
app.get('/api/sugestoes', requireAuth, (req, res) => {
  let q = `SELECT s.*,u.nome as autor_nome,u.setor as autor_setor FROM sugestoes s
    JOIN usuarios u ON s.autor_id=u.id WHERE 1=1`;
  const p = [];
  if (req.usuario.role!=='admin') { q += ' AND s.autor_id=?'; p.push(req.usuario.id); }
  if (req.query.status) { q += ' AND s.status=?'; p.push(req.query.status); }
  q += ' ORDER BY s.criado_em DESC';
  res.json(db.prepare(q).all(...p));
});

app.post('/api/sugestoes', requireAuth, (req, res) => {
  const { titulo, descricao, categoria } = req.body;
  if (!titulo||!descricao) return res.status(400).json({ erro: 'Título e descrição obrigatórios' });
  const r = db.prepare('INSERT INTO sugestoes (titulo,descricao,categoria,autor_id) VALUES (?,?,?,?)')
    .run(titulo, descricao, categoria||'Processo', req.usuario.id);
  db.prepare('INSERT INTO historico_sugestoes (sugestao_id,autor_nome,descricao) VALUES (?,?,?)')
    .run(r.lastInsertRowid, req.usuario.nome, 'Sugestão registrada');
  const admins = db.prepare("SELECT id,email FROM usuarios WHERE role='admin' AND ativo=1").all();
  admins.forEach(a => notificar(a.id,'nova_sugestao',`Nova sugestão: ${titulo}`,`Por ${req.usuario.nome}`,'/admin.html'));
  res.status(201).json({ id: r.lastInsertRowid });
});

app.get('/api/sugestoes/:id', requireAuth, (req, res) => {
  const s = db.prepare('SELECT s.*,u.nome as autor_nome,u.setor as autor_setor FROM sugestoes s JOIN usuarios u ON s.autor_id=u.id WHERE s.id=?').get(req.params.id);
  if (!s) return res.status(404).json({ erro: 'Não encontrado' });
  if (req.usuario.role!=='admin' && s.autor_id!==req.usuario.id) return res.status(403).json({ erro: 'Acesso negado' });
  const historico = db.prepare('SELECT * FROM historico_sugestoes WHERE sugestao_id=? ORDER BY criado_em ASC').all(s.id);
  res.json({ ...s, historico });
});

app.put('/api/sugestoes/:id', requireAuth, requireAdmin, (req, res) => {
  const s = db.prepare('SELECT * FROM sugestoes WHERE id=?').get(req.params.id);
  if (!s) return res.status(404).json({ erro: 'Não encontrado' });
  const { status, comentario } = req.body;
  const mudancas = [];
  if (status && status!==s.status) mudancas.push(`Status: "${s.status}" → "${status}"`);
  if (comentario) mudancas.push(comentario);
  db.prepare('UPDATE sugestoes SET status=?,atualizado_em=? WHERE id=?').run(status||s.status, agora(), s.id);
  if (mudancas.length) {
    db.prepare('INSERT INTO historico_sugestoes (sugestao_id,autor_nome,descricao) VALUES (?,?,?)')
      .run(s.id, req.usuario.nome, mudancas.join(' | '));
    notificar(s.autor_id,'sugestao_atualizada',`Sugestão atualizada: ${s.titulo}`,mudancas.join('. '),'/app.html');
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  NOTIFICAÇÕES
// ══════════════════════════════════════════════════════════════
app.get('/api/notificacoes', requireAuth, (req, res) => {
  const n = db.prepare('SELECT * FROM notificacoes WHERE usuario_id=? ORDER BY criado_em DESC LIMIT 50').all(req.usuario.id);
  const nao_lidas = db.prepare('SELECT COUNT(*) as n FROM notificacoes WHERE usuario_id=? AND lida=0').get(req.usuario.id).n;
  res.json({ notificacoes: n, nao_lidas });
});

app.put('/api/notificacoes/marcar-lidas', requireAuth, (req, res) => {
  db.prepare('UPDATE notificacoes SET lida=1 WHERE usuario_id=?').run(req.usuario.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  DASHBOARD (admin)
// ══════════════════════════════════════════════════════════════
app.get('/api/dashboard/stats', requireAuth, requireAdmin, (req, res) => {
  const periodo = req.query.periodo || 'mes';
  const filtros = {
    hoje:   "date(c.criado_em)=date('now','localtime')",
    semana: "c.criado_em >= datetime('now','localtime','-7 days')",
    mes:    "c.criado_em >= datetime('now','localtime','-30 days')",
    ano:    "strftime('%Y',c.criado_em)=strftime('%Y',datetime('now','localtime'))",
    tudo:   '1=1',
  };
  const filtro = filtros[periodo] || filtros.mes;

  const total      = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE ${filtro}`).get().n;
  const abertos    = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Aberto' AND ${filtro}`).get().n;
  const andamento  = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Em Andamento' AND ${filtro}`).get().n;
  const concluidos = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Concluido' AND ${filtro}`).get().n;
  const cancelados = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Cancelado' AND ${filtro}`).get().n;
  const criticos   = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE prioridade='Critica' AND status NOT IN ('Concluido','Cancelado')`).get().n;
  const atrasados  = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status NOT IN ('Concluido','Cancelado') AND sla_limite < datetime('now','localtime')`).get().n;

  // Tempo médio de atendimento (abertura → primeiro_atendimento_em) em horas
  const tma_row = db.prepare(`SELECT AVG((julianday(primeiro_atendimento_em)-julianday(criado_em))*24) as v FROM chamados c WHERE primeiro_atendimento_em IS NOT NULL AND ${filtro}`).get();
  const tma = tma_row.v ? parseFloat(tma_row.v.toFixed(1)) : null;

  // Tempo médio de resolução (abertura → fechado_em) em horas
  const tmr_row = db.prepare(`SELECT AVG((julianday(fechado_em)-julianday(criado_em))*24) as v FROM chamados c WHERE fechado_em IS NOT NULL AND status='Concluido' AND ${filtro}`).get();
  const tmr = tmr_row.v ? parseFloat(tmr_row.v.toFixed(1)) : null;

  // SLA cumprido vs violado
  const sla_cumprido  = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Concluido' AND fechado_em <= sla_limite AND ${filtro}`).get().n;
  const sla_violado   = db.prepare(`SELECT COUNT(*) as n FROM chamados c WHERE status='Concluido' AND fechado_em > sla_limite AND ${filtro}`).get().n;

  // Avaliação média
  const avaliacao_row = db.prepare(`SELECT AVG(a.nota) as v, COUNT(*) as n FROM avaliacoes a JOIN chamados c ON a.chamado_id=c.id WHERE ${filtro}`).get();
  const avaliacao_media = avaliacao_row.v ? parseFloat(avaliacao_row.v.toFixed(1)) : null;

  // Por setor
  const por_setor = db.prepare(`SELECT c.setor, COUNT(*) as n FROM chamados c WHERE ${filtro} GROUP BY c.setor ORDER BY n DESC`).all();

  // Por categoria
  const por_categoria = db.prepare(`SELECT categoria, COUNT(*) as n FROM chamados c WHERE ${filtro} GROUP BY categoria ORDER BY n DESC`).all();

  // Por prioridade
  const por_prioridade = db.prepare(`SELECT prioridade, COUNT(*) as n FROM chamados c WHERE ${filtro} GROUP BY prioridade ORDER BY n DESC`).all();

  // Por usuário (top 10)
  const por_usuario = db.prepare(`SELECT u.nome, u.setor, COUNT(*) as n FROM chamados c JOIN usuarios u ON c.solicitante_id=u.id WHERE ${filtro} GROUP BY c.solicitante_id ORDER BY n DESC LIMIT 10`).all();

  // Evolução por dia (últimos 30 dias)
  const evolucao = db.prepare(`SELECT date(criado_em) as dia, COUNT(*) as n FROM chamados WHERE criado_em >= datetime('now','localtime','-30 days') GROUP BY dia ORDER BY dia`).all();

  // Chamados recorrentes (mesmo setor + mesma categoria, >= 3 ocorrências no período)
  const recorrentes = db.prepare(`SELECT setor, categoria, COUNT(*) as n FROM chamados c WHERE ${filtro} GROUP BY setor,categoria HAVING n >= 3 ORDER BY n DESC LIMIT 10`).all();

  // Ranking setores
  const ranking_setores = por_setor.slice(0,10);

  // Problemas mais frequentes (por categoria)
  const problemas_freq = por_categoria.slice(0,10);

  // Chamados em atraso (detalhado)
  const lista_atrasados = db.prepare(`SELECT c.*,u.nome as solicitante_nome,u.setor as solicitante_setor FROM chamados c
    JOIN usuarios u ON c.solicitante_id=u.id WHERE c.status NOT IN ('Concluido','Cancelado') AND c.sla_limite < datetime('now','localtime')
    ORDER BY c.sla_limite ASC LIMIT 20`).all();

  // Avaliações recentes
  const avaliacoes_recentes = db.prepare(`SELECT a.*,u.nome as usuario_nome,c.titulo as chamado_titulo,c.protocolo FROM avaliacoes a
    JOIN usuarios u ON a.usuario_id=u.id JOIN chamados c ON a.chamado_id=c.id ORDER BY a.criado_em DESC LIMIT 10`).all();

  res.json({
    total, abertos, andamento, concluidos, cancelados, criticos, atrasados,
    tma, tmr, sla_cumprido, sla_violado, avaliacao_media,
    por_setor, por_categoria, por_prioridade, por_usuario,
    evolucao, recorrentes, ranking_setores, problemas_freq,
    lista_atrasados, avaliacoes_recentes,
  });
});

// Sugestões stats
app.get('/api/dashboard/sugestoes', requireAuth, requireAdmin, (req, res) => {
  const total    = db.prepare("SELECT COUNT(*) as n FROM sugestoes").get().n;
  const abertas  = db.prepare("SELECT COUNT(*) as n FROM sugestoes WHERE status='Aberta'").get().n;
  const analise  = db.prepare("SELECT COUNT(*) as n FROM sugestoes WHERE status='Em Análise'").get().n;
  const aprovadas= db.prepare("SELECT COUNT(*) as n FROM sugestoes WHERE status='Aprovada'").get().n;
  const implantadas = db.prepare("SELECT COUNT(*) as n FROM sugestoes WHERE status='Implementada'").get().n;
  const recentes = db.prepare("SELECT s.*,u.nome as autor_nome,u.setor as autor_setor FROM sugestoes s JOIN usuarios u ON s.autor_id=u.id ORDER BY s.criado_em DESC LIMIT 10").all();
  res.json({ total, abertas, analise, aprovadas, implantadas, recentes });
});

// ─── Iniciar ──────────────────────────────────────────────────
require('./auth-reset')(app, db, agora);
app.listen(PORT, () => {
  console.log(`\n✅ Oxipress Chamados v2 rodando em http://localhost:${PORT}`);
  console.log(`   Admin: admin@oxipress.com.br / Admin@2024\n`);
});
