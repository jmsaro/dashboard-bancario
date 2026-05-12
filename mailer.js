'use strict';

/**
 * mailer.js — Módulo de envío de correos vía SMTP (Nodemailer)
 * Carga credenciales desde variables de entorno con dotenv.
 */
require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT, 10) || 587,
  secure: process.env.SMTP_PORT === '465',
  auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  connectionTimeout: 10_000,
  greetingTimeout:   5_000,
});

async function verifyConnection() {
  try {
    await transporter.verify();
    console.log(`[SMTP] Conexión verificada — ${process.env.SMTP_HOST}:${process.env.SMTP_PORT}`);
    return true;
  } catch (err) {
    throw new Error(`No se pudo conectar al servidor SMTP: ${err.message}`);
  }
}

async function sendMail(to, subject, htmlContent) {
  if (!to || to.trim() === '') throw new Error('El destinatario no puede estar vacío');
  const ts = new Date().toISOString();
  console.log(`[CORREO ${ts}] Para: ${to} | Asunto: ${subject}`);
  const resultado = await transporter.sendMail({
    from: process.env.SMTP_FROM || `KYC Risk Monitor <${process.env.SMTP_USER}>`,
    to: to.trim(), subject, html: htmlContent,
  });
  console.log(`[CORREO] Enviado — MessageId: ${resultado.messageId}`);
  return { success: true, messageId: resultado.messageId };
}

module.exports = { sendMail, verifyConnection };
