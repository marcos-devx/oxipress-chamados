const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) throw new Error('JWT_SECRET nao configurado. Defina a variavel de ambiente.');

function gerarToken(usuario) {
  return jwt.sign(
    { id: usuario.id, email: usuario.email, role: usuario.role, nome: usuario.nome, setor: usuario.setor },
    SECRET,
    { expiresIn: process.env.JWT_EXPIRES || '8h' }
  );
}

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

function requireAdmin(req, res, next) {
  if (req.usuario?.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });
  next();
}

module.exports = { gerarToken, requireAuth, requireAdmin };
