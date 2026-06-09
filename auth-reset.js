const bcrypt = require('bcryptjs');
const mailer = require('./mailer');

module.exports = function(app, db, agora) {

    // POST /api/auth/forgot-password
    app.post('/api/auth/forgot-password', (req, res) => {
          const { email } = req.body;
          if (!email) return res.status(400).json({ erro: 'E-mail obrigatorio' });
          const u = db.prepare('SELECT * FROM usuarios WHERE email = ? AND ativo = 1').get(email.toLowerCase().trim());
          if (!u) return res.json({ ok: true }); // nao revelar se email existe
                 const token = require('crypto').randomBytes(32).toString('hex');
          const expira = new Date(Date.now() + 3600000).toISOString().replace('T',' ').slice(0,19);
          db.prepare('UPDATE reset_tokens SET usado = 1 WHERE usuario_id = ?').run(u.id);
          db.prepare('INSERT INTO reset_tokens (usuario_id, token, expira_em) VALUES (?, ?, ?)').run(u.id, token, expira);
          const link = (process.env.BASE_URL || ('https://'+req.get('host'))) + '/reset-senha.html?token=' + token;
          mailer.enviar({ para: u.email, assunto: 'Redefinicao de Senha - Chamados TI', html: mailer.htmlResetSenha(u.nome, link) });
          res.json({ ok: true });
    });

    // POST /api/auth/reset-password
    app.post('/api/auth/reset-password', (req, res) => {
          const { token, senha } = req.body;
          if (!token || !senha) return res.status(400).json({ erro: 'Token e senha obrigatorios' });
          if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres' });
          const now = agora();
          const rt = db.prepare('SELECT * FROM reset_tokens WHERE token = ? AND usado = 0 AND expira_em > ?').get(token, now);
          if (!rt) return res.status(400).json({ erro: 'Link invalido ou expirado' });
          db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(bcrypt.hashSync(senha, 10), rt.usuario_id);
          db.prepare('UPDATE reset_tokens SET usado = 1 WHERE token = ?').run(token);
          res.json({ ok: true });
    });

};
