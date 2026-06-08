require('dotenv').config();
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'chamados.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    nome          TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    senha_hash    TEXT    NOT NULL,
    setor         TEXT    NOT NULL,
    cargo         TEXT    DEFAULT '',
    role          TEXT    NOT NULL DEFAULT 'usuario',
    ativo         INTEGER NOT NULL DEFAULT 1,
    criado_em     TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
    ultimo_acesso TEXT
  );

  CREATE TABLE IF NOT EXISTS chamados (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    protocolo              TEXT    NOT NULL UNIQUE,
    titulo                 TEXT    NOT NULL,
    descricao              TEXT    NOT NULL,
    categoria              TEXT    NOT NULL,
    prioridade             TEXT    NOT NULL DEFAULT 'Media',
    status                 TEXT    NOT NULL DEFAULT 'Aberto',
    setor                  TEXT    NOT NULL,
    solicitante_id         INTEGER NOT NULL REFERENCES usuarios(id),
    responsavel_id         INTEGER REFERENCES usuarios(id),
    sla_limite             TEXT,
    primeiro_atendimento_em TEXT,
    fechado_em             TEXT,
    criado_em              TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
    atualizado_em          TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS historico_chamados (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chamado_id  INTEGER NOT NULL REFERENCES chamados(id),
    autor_id    INTEGER REFERENCES usuarios(id),
    autor_nome  TEXT    NOT NULL,
    tipo        TEXT    NOT NULL,
    descricao   TEXT    NOT NULL,
    criado_em   TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS anexos (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chamado_id     INTEGER NOT NULL REFERENCES chamados(id),
    nome_original  TEXT    NOT NULL,
    nome_arquivo   TEXT    NOT NULL,
    tamanho        INTEGER,
    mime_type      TEXT,
    criado_em      TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS avaliacoes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chamado_id  INTEGER NOT NULL UNIQUE REFERENCES chamados(id),
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id),
    nota        INTEGER NOT NULL CHECK(nota BETWEEN 1 AND 5),
    comentario  TEXT    DEFAULT '',
    criado_em   TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS sugestoes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo      TEXT    NOT NULL,
    descricao   TEXT    NOT NULL,
    categoria   TEXT    NOT NULL DEFAULT 'Processo',
    status      TEXT    NOT NULL DEFAULT 'Aberta',
    autor_id    INTEGER NOT NULL REFERENCES usuarios(id),
    criado_em   TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
    atualizado_em TEXT  NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS historico_sugestoes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sugestao_id  INTEGER NOT NULL REFERENCES sugestoes(id),
    autor_nome   TEXT    NOT NULL,
    descricao    TEXT    NOT NULL,
    criado_em    TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS notificacoes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id),
    tipo        TEXT    NOT NULL,
    titulo      TEXT    NOT NULL,
    mensagem    TEXT    NOT NULL,
    link        TEXT    DEFAULT '',
    lida        INTEGER NOT NULL DEFAULT 0,
    criado_em   TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  );
`);

// ─── Seed: admin padrão ───────────────────────────────────────
const adminExiste = db.prepare("SELECT id FROM usuarios WHERE role='admin' LIMIT 1").get();
if (!adminExiste) {
  const hash = bcrypt.hashSync('Admin@2024', 10);
  db.prepare(`INSERT INTO usuarios (nome, email, senha_hash, setor, cargo, role)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run('Administrador TI', 'admin@oxipress.com.br', hash, 'TI', 'Administrador', 'admin');
  console.log('✅ Admin padrão criado: admin@oxipress.com.br / Admin@2024');
}

module.exports = db;
