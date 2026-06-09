require('dotenv').config();
const nodemailer = require('nodemailer');

let transporter = null;

function getTransporter() {
    if (!transporter && process.env.SMTP_USER && process.env.SMTP_USER !== 'seu_email@gmail.com') {
          transporter = nodemailer.createTransport({
                  host: process.env.SMTP_HOST || 'smtp.gmail.com',
                  port: parseInt(process.env.SMTP_PORT || '587'),
                  secure: process.env.SMTP_PORT === '465',
                  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
          });
    }
    return transporter;
}

async function enviar({ para, assunto, html }) {
    const t = getTransporter();
    if (!t) { console.log(`[Mailer] Nao configurado. Pulando: ${assunto}`); return; }
    try {
          await t.sendMail({ from: process.env.EMAIL_FROM, to: para, subject: assunto, html });
          console.log(`[Mailer] Enviado -> ${para}`);
    } catch (e) { console.error('[Mailer] Erro:', e.message); }
}

const base = process.env.BASE_URL || 'http://localhost:3000';

function htmlNovoChamado(c, solicitante) {
    return wrap(`
        <h2 style="color:#1d4ed8">Novo Chamado - ${c.protocolo}</h2>
            <table style="width:100%;border-collapse:collapse;margin:16px 0">
                  <tr><td style="color:#6b7280;padding:6px 0;width:130px">Solicitante</td><td><strong>${solicitante}</strong></td></tr>
                        <tr><td style="color:#6b7280;padding:6px 0">Titulo</td><td>${c.titulo}</td></tr>
                              <tr><td style="color:#6b7280;padding:6px 0">Categoria</td><td>${c.categoria}</td></tr>
                                    <tr><td style="color:#6b7280;padding:6px 0">Prioridade</td><td><strong style="color:${corPrio(c.prioridade)}">${c.prioridade}</strong></td></tr>
                                          <tr><td style="color:#6b7280;padding:6px 0">Setor</td><td>${c.setor}</td></tr>
                                              </table>
                                                  <p style="background:#f8fafc;padding:12px;border-radius:6px;color:#374151">${c.descricao}</p>
                                                      <a href="${base}/admin.html" style="display:inline-block;margin-top:16px;background:#1d4ed8;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Ver no Painel</a>
                                                        `);
}

function htmlAtualizacao(c, historico) {
    return wrap(`
        <h2 style="color:#0f766e">Chamado Atualizado - ${c.protocolo}</h2>
            <p><strong>${c.titulo}</strong></p>
                <p>Status atual: <strong>${c.status}</strong></p>
                    <p style="background:#f0fdf4;padding:12px;border-radius:6px;color:#374151;margin-top:12px">${historico.descricao}</p>
                        <a href="${base}/app.html" style="display:inline-block;margin-top:16px;background:#0f766e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Ver Chamado</a>
                          `);
}

function htmlConcluido(c) {
    return wrap(`
        <h2 style="color:#15803d">Chamado Concluido - ${c.protocolo}</h2>
            <p><strong>${c.titulo}</strong></p>
                <p>Seu chamado foi concluido. Por favor, avalie o atendimento.</p>
                    <a href="${base}/app.html" style="display:inline-block;margin-top:16px;background:#15803d;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Avaliar Atendimento</a>
                      `);
}

function htmlResetSenha(nome, link) {
    return wrap(`
        <h2 style="color:#1d4ed8">Redefinicao de Senha</h2>
            <p>Ola, <strong>${nome}</strong>!</p>
                <p>Recebemos uma solicitacao para redefinir a senha da sua conta no sistema Chamados TI.</p>
                    <p>Clique no botao abaixo para criar uma nova senha. O link e valido por <strong>1 hora</strong>.</p>
                        <a href="${link}" style="display:inline-block;margin-top:16px;background:#1d4ed8;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Redefinir Senha</a>
                            <p style="margin-top:20px;font-size:13px;color:#6b7280">Se voce nao solicitou a redefinicao, ignore este e-mail. Sua senha permanece a mesma.</p>
                              `);
}

function wrap(content) {
    return `<div style="font-family:sans-serif;max-width:600px;margin:auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
    <div style="background:#1e293b;padding:16px 20px"><p style="color:#fff;margin:0;font-weight:bold">Chamados TI - Oxipress</p></div>
    <div style="padding:24px">${content}</div>
    <div style="background:#f8fafc;padding:12px 20px;font-size:12px;color:#9ca3af">Este e um e-mail automatico. Nao responda.</div>
    </div>`;
}

function corPrio(p) { return {Critica:'#dc2626',Alta:'#ea580c',Media:'#ca8a04',Baixa:'#16a34a'}[p]||'#374151'; }

module.exports = { enviar, htmlNovoChamado, htmlAtualizacao, htmlConcluido, htmlResetSenha };
