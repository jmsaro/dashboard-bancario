'use strict';

/**
 * server.js
 * Servidor Express para KYC Risk Monitor.
 * Módulos: envío de correos regulatorios, validación RENAPO/RFC,
 * detección de duplicidades y auditoría en memoria.
 * Diseñado para despliegue en Railway.
 */

require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const { v4: uuidv4 } = require('uuid');
const ExcelJS = require('exceljs');

const { sendMail, verifyConnection } = require('./mailer');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ================================================================
   MIDDLEWARE
   ================================================================ */
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname)));

/* ================================================================
   ALMACENAMIENTO EN MEMORIA
   ================================================================ */
let auditLog             = [];   // Registro de comunicaciones enviadas
let validacionResultados = null; // Últimos resultados de validación masiva RENAPO

/* ================================================================
   CONSTANTES — CORREO
   ================================================================ */
const TIPOS_VALIDOS = {
  aviso_privacidad: 'Aviso de Privacidad',
  cita_sucursal:    'Cita en Sucursal',
  datos_pendientes: 'Datos Pendientes',
};
const TEMPLATE_MAP = {
  aviso_privacidad: 'aviso-privacidad.html',
  cita_sucursal:    'cita-sucursal.html',
  datos_pendientes: 'datos-pendientes.html',
};
const ASUNTO_MAP = {
  aviso_privacidad: 'Aviso de Privacidad',
  cita_sucursal:    'Solicitud de Cita en Sucursal',
  datos_pendientes: 'Actualización de Datos Requerida',
};
const COLOR_SEMAFORO = {
  rojo:     { fondo: 'FFFDECEA', texto: 'FFC0392B' },
  amarillo: { fondo: 'FFFFF9E6', texto: 'FF9A6700' },
  verde:    { fondo: 'FFE8FAF1', texto: 'FF1E8449' },
};

/* ================================================================
   CONSTANTES — RFC / CURP / VALIDACIÓN
   ================================================================ */
const CURP_REGEX = /^[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[A-Z0-9]{2}$/;

const RFC_INCONVENIENTES = [
  'BACA','BAKA','BUEI','BUEY','CACA','CACO','CAGA','CAGO','CAKA','CAKO',
  'COGE','COGI','COJA','COJE','COJI','COJO','COLA','CULO','FALO','FETO',
  'GETA','GUEI','GUEY','JETA','JOTO','KACA','KACO','KAGA','KAGO','KAKA',
  'KAKO','KOGE','KOGI','KOJA','KOJE','KOJI','KOJO','KOLA','KULO','LELA',
  'LELO','LOCA','LOCO','LOKA','LOKO','MAME','MAMO','MEAR','MEAS','MEON',
  'MIAR','MION','MOCO','MOKO','MULA','MULO','NACA','NACO','PEDA','PEDO',
  'PENE','PIPI','PITO','POPO','PUTA','PUTO','QULO','RATA','ROBA','ROBE',
  'ROBO','RUIN','SENO','TETA','VACA','VAGA','VAGO','VAKA','VUEI','VUEY',
  'WUEI','WUEY',
];
const PARTICULAS      = new Set(['DE','DEL','LA','LAS','LOS','Y','MC','MAC','VAN','VON']);
const NOMBRES_EXCLUIR = new Set(['MARIA','MA','JOSE','J']);
const VOCALES         = new Set(['A','E','I','O','U']);

// Tabla de valores para cálculo de homoclave (algoritmo SAT)
const HC_VALS = {
  ' ':0,'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,
  'A':10,'B':11,'C':12,'D':13,'E':14,'F':15,'G':16,'H':17,'I':18,'J':19,
  'K':20,'L':21,'M':22,'N':23,'Ñ':24,'O':25,'P':26,'Q':27,'R':28,'S':29,
  'T':30,'U':31,'V':32,'W':33,'X':34,'Y':35,'Z':36,
};
const HC_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/* ================================================================
   UTILIDADES GENERALES
   ================================================================ */
function timestampMexico() {
  const ahora    = new Date();
  const mexicoMs = ahora.getTime() + (-6 * 3600_000);
  return new Date(mexicoMs).toISOString().replace('Z', '-06:00');
}

function fechaEspanol() {
  return new Date().toLocaleDateString('es-MX', { year: 'numeric', month: 'long', day: 'numeric' });
}

function renderTemplate(html, vars) {
  return html.replace(/\{\{(\w+)\}\}/g, (_, k) =>
    vars[k] !== undefined ? String(vars[k]) : `{{${k}}}`
  );
}

function filenameTimestamp() {
  const n = new Date();
  const p = v => String(v).padStart(2, '0');
  return `${n.getFullYear()}${p(n.getMonth()+1)}${p(n.getDate())}_${p(n.getHours())}${p(n.getMinutes())}${p(n.getSeconds())}`;
}

/* ================================================================
   UTILIDADES RFC / CURP
   ================================================================ */

/**
 * Normaliza un string: mayúsculas, sin acentos, solo A-Z y espacios.
 */
function normStr(s) {
  return String(s || '')
    .toUpperCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Z0-9 ]/g, '')
    .trim();
}

/**
 * Genera los 10 caracteres base del RFC según el algoritmo oficial del SAT.
 * Retorna null si los datos son insuficientes.
 */
function generarRFCBase(nombre, apPaterno, apMaterno, fechaNacimiento) {
  const ap = normStr(apPaterno).split(' ').filter(p => p && !PARTICULAS.has(p)).join('');
  const am = normStr(apMaterno || '').split(' ').filter(p => p && !PARTICULAS.has(p));
  const nomParts = normStr(nombre).split(' ').filter(p => p && !PARTICULAS.has(p));

  if (!ap || !nomParts.length) return null;

  // Primera letra + primera vocal interna del apellido paterno
  const l1                = ap.charAt(0);
  const primeraVocalInter = [...ap.slice(1)].find(c => VOCALES.has(c)) || 'X';

  // Primera letra del apellido materno (o X si no hay)
  const l3 = (am[0] || '').charAt(0) || 'X';

  // Primera letra del nombre (saltar MARIA/JOSE si hay segundo nombre)
  let nomUsar = nomParts[0];
  if (nomParts.length > 1 && NOMBRES_EXCLUIR.has(nomParts[0])) {
    nomUsar = nomParts[1];
  }
  const l4 = nomUsar.charAt(0);

  // Fecha AAMMDD
  const f = new Date(`${fechaNacimiento}T12:00:00`);
  if (isNaN(f.getTime())) return null;
  const aa = String(f.getFullYear()).slice(-2);
  const mm = String(f.getMonth() + 1).padStart(2, '0');
  const dd = String(f.getDate()).padStart(2, '0');

  let base = `${l1}${primeraVocalInter}${l3}${l4}${aa}${mm}${dd}`;

  // Reemplazar palabra inconveniente en los primeros 4 caracteres
  if (RFC_INCONVENIENTES.includes(base.slice(0, 4))) {
    base = base.slice(0, 3) + 'X' + base.slice(4);
  }

  return base;
}

/**
 * Calcula la homoclave de 3 caracteres usando el algoritmo oficial del SAT.
 */
function calcularHomoclave(apPaterno, apMaterno, nombre) {
  const cadena = normStr(`${apPaterno} ${apMaterno || ''} ${nombre}`);
  let suma = 0;
  for (let i = 0; i < cadena.length; i++) {
    suma = (suma + (i + 1) * (HC_VALS[cadena[i]] ?? 0)) % 1000;
  }
  const c1 = Math.floor(suma / 34) % HC_CHARS.length;
  const c2 = suma % HC_CHARS.length;
  const c3 = suma % 10;
  return (HC_CHARS[c1] || '0') + (HC_CHARS[c2] || '0') + c3;
}

/* ================================================================
   RUTAS — CORREO ELECTRÓNICO
   ================================================================ */

/** POST /api/send-email — Envío de correo regulatorio */
app.post('/api/send-email', async (req, res) => {
  const { tipo, cliente, remitente } = req.body;

  if (!TIPOS_VALIDOS[tipo]) {
    return res.status(400).json({ success: false,
      error: `Tipo inválido. Permitidos: ${Object.keys(TIPOS_VALIDOS).join(', ')}` });
  }
  if (!cliente?.email?.trim()) {
    return res.status(400).json({ success: false, error: 'cliente.email no puede estar vacío' });
  }

  const templatePath = path.join(__dirname, 'templates', TEMPLATE_MAP[tipo]);
  if (!fs.existsSync(templatePath)) {
    return res.status(500).json({ success: false, error: `Plantilla no encontrada: ${TEMPLATE_MAP[tipo]}` });
  }
  const templateHtml = fs.readFileSync(templatePath, 'utf8');

  const problemasHTML = Array.isArray(cliente.problemas) && cliente.problemas.length
    ? `<ul style="margin:6px 0;padding-left:20px;">${cliente.problemas.map(p => `<li>${p}</li>`).join('')}</ul>`
    : '<p style="margin:0;">Sin problemas específicos registrados.</p>';

  const folio        = uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase();
  const nombreBanco  = remitente?.nombre_banco || process.env.BANCO_NOMBRE || 'Banco';
  const emailBanco   = remitente?.email_banco  || process.env.BANCO_EMAIL  || '';
  const nombreCliente = `${cliente.nombre || ''} ${cliente.apellido || ''}`.trim();

  const vars = {
    nombre_cliente: nombreCliente,
    rfc_cliente:    cliente.rfc    || '—',
    email_cliente:  cliente.email,
    id_cliente:     cliente.id     || '—',
    score_global:   cliente.score  || '—',
    semaforo:       cliente.semaforo || '—',
    problemas:      problemasHTML,
    nombre_banco:   nombreBanco,
    email_banco:    emailBanco,
    fecha_actual:   fechaEspanol(),
    folio,
  };
  const htmlFinal = renderTemplate(templateHtml, vars);
  const asunto    = `${ASUNTO_MAP[tipo]} — ${nombreBanco}`;

  const entradaLog = {
    id_log:               uuidv4(),
    timestamp:            timestampMexico(),
    id_cliente:           cliente.id      || null,
    nombre_cliente:       nombreCliente,
    rfc_cliente:          cliente.rfc     || null,
    email_destino:        cliente.email.trim(),
    tipo_comunicacion:    TIPOS_VALIDOS[tipo],
    problemas_detectados: Array.isArray(cliente.problemas) ? cliente.problemas.join(', ') : '',
    score_riesgo_global:  cliente.score    || null,
    semaforo:             cliente.semaforo || null,
    usuario_operador:     req.headers['x-operador'] || 'sistema',
    nombre_banco:         nombreBanco,
    estado_envio:         'exitoso',
    detalle_error:        null,
  };

  try {
    await sendMail(cliente.email.trim(), asunto, htmlFinal);
    auditLog.push(entradaLog);
    return res.json({ success: true, mensaje: `Correo enviado a ${cliente.email.trim()}`, id_log: entradaLog.id_log });
  } catch (err) {
    entradaLog.estado_envio  = 'error';
    entradaLog.detalle_error = err.message;
    auditLog.push(entradaLog);
    return res.status(500).json({ success: false, error: err.message, id_log: entradaLog.id_log });
  }
});

/** GET /api/audit-log — Consulta del log con filtros */
app.get('/api/audit-log', (req, res) => {
  const { tipo, semaforo, desde, hasta } = req.query;
  let r = [...auditLog];
  if (tipo)    r = r.filter(x => x.tipo_comunicacion === TIPOS_VALIDOS[tipo]);
  if (semaforo) r = r.filter(x => x.semaforo === semaforo);
  if (desde)   r = r.filter(x => new Date(x.timestamp) >= new Date(`${desde}T00:00:00-06:00`));
  if (hasta)   r = r.filter(x => new Date(x.timestamp) <= new Date(`${hasta}T23:59:59-06:00`));
  return res.json({ total: r.length, registros: r });
});

/** GET /api/audit-log/export — Exportar Excel con 3 hojas */
app.get('/api/audit-log/export', async (req, res) => {
  try {
    const wb = new ExcelJS.Workbook();
    wb.creator = 'KYC Risk Monitor';
    wb.created = new Date();

    // ── Hoja 1: Comunicaciones ──
    const ws1 = wb.addWorksheet('Comunicaciones');
    ws1.columns = [
      { header: 'ID Log',            key: 'id_log',               width: 38 },
      { header: 'Timestamp (MX)',    key: 'timestamp',            width: 26 },
      { header: 'ID Cliente',        key: 'id_cliente',           width: 12 },
      { header: 'Nombre',            key: 'nombre_cliente',       width: 28 },
      { header: 'RFC',               key: 'rfc_cliente',          width: 16 },
      { header: 'Email',             key: 'email_destino',        width: 32 },
      { header: 'Tipo',              key: 'tipo_comunicacion',    width: 26 },
      { header: 'Problemas',         key: 'problemas_detectados', width: 42 },
      { header: 'Score',             key: 'score_riesgo_global',  width: 10 },
      { header: 'Semáforo',          key: 'semaforo',             width: 12 },
      { header: 'Operador',          key: 'usuario_operador',     width: 20 },
      { header: 'Banco',             key: 'nombre_banco',         width: 20 },
      { header: 'Estado',            key: 'estado_envio',         width: 12 },
      { header: 'Error',             key: 'detalle_error',        width: 36 },
    ];
    const h1 = ws1.getRow(1);
    h1.font      = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    h1.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1A3A5C' } };
    h1.alignment = { vertical: 'middle', horizontal: 'center' };
    h1.height    = 22;

    auditLog.forEach((r, idx) => {
      const fila = ws1.addRow({ ...r,
        score_riesgo_global: r.score_riesgo_global != null ? `${r.score_riesgo_global}%` : '—',
        semaforo: r.semaforo ? r.semaforo.charAt(0).toUpperCase() + r.semaforo.slice(1) : '—',
        detalle_error: r.detalle_error || '',
      });
      if (idx % 2 === 0) fila.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF8FAFC' } };
      const cols = COLOR_SEMAFORO[r.semaforo];
      if (cols) {
        const c = fila.getCell(10);
        c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: cols.fondo } };
        c.font = { bold: true, color: { argb: cols.texto } };
        c.alignment = { horizontal: 'center' };
      }
      fila.alignment = { wrapText: true, vertical: 'top' };
    });
    ws1.autoFilter = { from: 'A1', to: 'N1' };
    ws1.views = [{ state: 'frozen', ySplit: 1 }];

    // ── Hoja 2: Resumen ──
    const ws2 = wb.addWorksheet('Resumen');
    ws2.columns = [{ key: 'c', width: 34 }, { key: 'v', width: 16 }];
    const cnt = (fn) => auditLog.filter(fn).length;

    const addSec = (titulo, filas) => {
      const t = ws2.addRow([titulo]);
      t.getCell(1).font = { bold: true, size: 13, color: { argb: 'FF1A3A5C' } };
      t.height = 26;
      const h = ws2.addRow(['Categoría', 'Total']);
      ['A','B'].forEach(col => {
        const c = ws2.getCell(`${col}${h.number}`);
        c.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2C5F8A' } };
        c.alignment = { horizontal: 'center' };
      });
      filas.forEach(([cat, val], i) => {
        const fr = ws2.addRow([cat, val]);
        if (i % 2 === 0) {
          fr.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF4F6F9' } };
          fr.getCell(2).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF4F6F9' } };
        }
        fr.getCell(2).alignment = { horizontal: 'center' };
        fr.getCell(2).font = { bold: true };
      });
      ws2.addRow([]);
    };

    addSec('Totales por Tipo', [
      ['Aviso de Privacidad', cnt(r => r.tipo_comunicacion === 'Aviso de Privacidad')],
      ['Cita en Sucursal',    cnt(r => r.tipo_comunicacion === 'Cita en Sucursal')],
      ['Datos Pendientes',    cnt(r => r.tipo_comunicacion === 'Datos Pendientes')],
    ]);
    addSec('Totales por Semáforo', [
      ['Rojo',    cnt(r => r.semaforo === 'rojo')],
      ['Amarillo',cnt(r => r.semaforo === 'amarillo')],
      ['Verde',   cnt(r => r.semaforo === 'verde')],
    ]);
    addSec('Estado de Envío', [
      ['Exitosos', cnt(r => r.estado_envio === 'exitoso')],
      ['Con error', cnt(r => r.estado_envio === 'error')],
      ['Total', auditLog.length],
    ]);

    // ── Hoja 3: Metadata ──
    const ws3 = wb.addWorksheet('Metadata');
    ws3.columns = [{ key: 'c', width: 30 }, { key: 'v', width: 60 }];
    const ahora    = new Date();
    const fechaHoy = ahora.toLocaleDateString('es-MX', { year: 'numeric', month: 'long', day: 'numeric' });
    const horaHoy  = ahora.toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    ws3.addRow([]);
    const titleRow = ws3.addRow(['KYC Risk Monitor — Registro de Auditoría Regulatoria']);
    titleRow.getCell(1).font = { bold: true, size: 16, color: { argb: 'FF1A3A5C' } };
    titleRow.height = 32;
    ws3.addRow([]);
    [
      ['Institución Bancaria', process.env.BANCO_NOMBRE || '—'],
      ['Exportado el',         `${fechaHoy} a las ${horaHoy}`],
      ['Total registros',      String(auditLog.length)],
      ['Sistema',              'KYC Risk Monitor v1.0.0'],
    ].forEach(([c, v]) => {
      const fr = ws3.addRow([c, v]);
      fr.getCell(1).font = { bold: true };
      fr.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF4F6F9' } };
    });
    ws3.addRow([]);
    const notaRow = ws3.addRow(['Nota Regulatoria', 'Generado conforme a la CNBV, CONDUSEF y LFPDPPP. Documento confidencial de distribución restringida.']);
    notaRow.getCell(2).alignment = { wrapText: true };
    notaRow.getCell(2).font = { italic: true, color: { argb: 'FF666666' } };
    notaRow.height = 40;

    const filename = `AuditLog_KYC_${filenameTimestamp()}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ success: false, error: err.message });
  }
});

/** POST /api/audit-log/clear — Limpiar log (solo demo) */
app.post('/api/audit-log/clear', (req, res) => {
  const n = auditLog.length;
  auditLog = [];
  return res.json({ success: true, registros_eliminados: n });
});

/* ================================================================
   RUTAS — VALIDACIÓN DE IDENTIDAD (RENAPO / RFC)
   ================================================================ */

/**
 * POST /api/validar-curp
 * Valida el formato CURP y consulta la API pública de RENAPO.
 * Maneja timeout de 10 segundos.
 */
app.post('/api/validar-curp', async (req, res) => {
  const { curp } = req.body;

  if (!curp || !CURP_REGEX.test(curp.trim().toUpperCase())) {
    return res.status(400).json({
      existe: false,
      error: 'Formato CURP inválido (debe tener 18 caracteres y cumplir el patrón oficial)',
    });
  }

  const curpNorm = curp.trim().toUpperCase();

  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 10_000);

    const resp = await fetch(
      `https://consultas.curp.gob.mx/CurpSP/rest/consultaCurp/${curpNorm}`,
      { signal: controller.signal, headers: { 'Accept': 'application/json' } }
    );
    clearTimeout(tid);

    if (!resp.ok) {
      return res.json({ existe: false, error: 'CURP no encontrada en RENAPO' });
    }

    const datos = await resp.json();

    if (datos && (datos.nombre || datos.primerApellido)) {
      return res.json({
        existe: true,
        datos_renapo: {
          nombre:          datos.nombre               || null,
          primerApellido:  datos.primerApellido        || null,
          segundoApellido: datos.segundoApellido       || null,
          fechaNacimiento: datos.fechNac || datos.fechaNacimiento || null,
          sexo:            datos.sexo                 || null,
          claveEntidad:    datos.claveEntidadRegistro || datos.claveEntidad || null,
          estatus:         datos.statusCurp           || datos.estatus || null,
        },
      });
    }

    return res.json({ existe: false, error: 'CURP no encontrada en RENAPO' });

  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ existe: false, error: 'Timeout: RENAPO no respondió en 10 segundos' });
    }
    console.error('[RENAPO] Error:', err.message);
    return res.status(502).json({ existe: false, error: `Error de red al consultar RENAPO: ${err.message}` });
  }
});

/**
 * POST /api/validar-rfc
 * Genera el RFC con el algoritmo oficial del SAT y lo compara con el registrado.
 */
app.post('/api/validar-rfc', (req, res) => {
  const { nombre, apellido_paterno, apellido_materno, fecha_nacimiento, rfc_registrado } = req.body;

  if (!nombre || !apellido_paterno || !fecha_nacimiento) {
    return res.status(400).json({ valido: false, error: 'Se requieren nombre, apellido_paterno y fecha_nacimiento' });
  }

  const rfcBase = generarRFCBase(nombre, apellido_paterno, apellido_materno || '', fecha_nacimiento);
  if (!rfcBase) {
    return res.status(400).json({ valido: false, error: 'Fecha de nacimiento inválida o datos insuficientes' });
  }

  const homoclave   = calcularHomoclave(apellido_paterno, apellido_materno || '', nombre);
  const rfcGenerado = rfcBase + homoclave;

  if (!rfc_registrado) {
    return res.json({ valido: true, rfc_generado: rfcGenerado, coincide: 'no_registrado' });
  }

  const rfcReg       = rfc_registrado.trim().toUpperCase();
  const base10gen    = rfcGenerado.slice(0, 10);
  const base10reg    = rfcReg.slice(0, 10);

  if (rfcReg === rfcGenerado) {
    return res.json({ valido: true, coincide: true, rfc_generado: rfcGenerado });
  }

  if (base10gen === base10reg) {
    return res.json({
      valido: true, coincide: 'parcial',
      nota: 'La base RFC (10 chars) coincide pero la homoclave difiere',
      rfc_generado: rfcGenerado, rfc_registrado: rfcReg,
    });
  }

  return res.json({
    valido: false, coincide: false,
    rfc_generado: rfcGenerado, rfc_registrado: rfcReg,
    diferencia: `Base generada: ${base10gen} vs registrada: ${base10reg}`,
  });
});

/**
 * POST /api/detectar-duplicados
 * Detecta duplicidades en RFC, CURP, nombre+fecha, email e impersonamiento.
 */
app.post('/api/detectar-duplicados', (req, res) => {
  const { clientes } = req.body;
  if (!Array.isArray(clientes) || !clientes.length) {
    return res.status(400).json({ error: 'Se requiere un array de clientes no vacío' });
  }

  const duplicadosRFC      = [];
  const duplicadosCURP     = [];
  const duplicadosNomFecha = [];
  const duplicadosEmail    = [];
  const alertasImpers      = [];

  // Agrupar por clave y devolver solo grupos con >1 elemento
  const agrupar = (items, keyFn) => {
    const m = {};
    items.forEach(c => {
      const k = keyFn(c);
      if (!k) return;
      (m[k] = m[k] || []).push(c);
    });
    return Object.entries(m).filter(([, g]) => g.length > 1);
  };

  // Resumir cliente para la lista de afectados
  const resumir = c => ({ id: c.id, nombre: `${c.nombre} ${c.apellido}`.trim(), rfc: c.rfc, curp: c.curp, email: c.email });

  // 1 — RFC exacto
  agrupar(clientes, c => String(c.rfc || '').trim().toUpperCase() || null)
    .forEach(([rfc, grupo]) => {
      duplicadosRFC.push({ tipo: 'RFC duplicado', valor: rfc, clientes_afectados: grupo.map(resumir) });
      // Si distintos nombres → impersonamiento
      const nombres = [...new Set(grupo.map(c => normStr(`${c.nombre} ${c.apellido}`)))];
      if (nombres.length > 1) {
        alertasImpers.push({
          tipo: 'Posible impersonamiento',
          descripcion: `RFC "${rfc}" está asociado a múltiples identidades distintas`,
          clientes_afectados: grupo.map(resumir),
        });
      }
    });

  // 2 — CURP exacta (solo CURPs con formato válido)
  agrupar(clientes, c => {
    const s = String(c.curp || '').trim().toUpperCase();
    return CURP_REGEX.test(s) ? s : null;
  }).forEach(([curp, grupo]) =>
    duplicadosCURP.push({ tipo: 'CURP duplicada', valor: curp, clientes_afectados: grupo.map(resumir) })
  );

  // 3 — Nombre completo + fecha de nacimiento
  agrupar(clientes, c => {
    const nom   = normStr(`${c.nombre} ${c.apellido}`);
    const fecha = String(c.fecha_nacimiento || '').trim();
    return nom && fecha ? `${nom}|${fecha}` : null;
  }).forEach(([clave, grupo]) => {
    const [nombre, fecha] = clave.split('|');
    duplicadosNomFecha.push({ tipo: 'Nombre y fecha de nacimiento duplicados', valor: `${nombre} / ${fecha}`, clientes_afectados: grupo.map(resumir) });
    // Distintos RFC o CURP → identidad duplicada sospechosa
    const rfcs  = [...new Set(grupo.map(c => String(c.rfc  || '').toUpperCase()).filter(Boolean))];
    const curps = [...new Set(grupo.map(c => String(c.curp || '').toUpperCase()).filter(Boolean))];
    if (rfcs.length > 1 || curps.length > 1) {
      alertasImpers.push({
        tipo: 'Posible duplicidad de identidad',
        descripcion: `"${nombre}" (${fecha}) aparece con distintos RFC o CURP`,
        clientes_afectados: grupo.map(resumir),
      });
    }
  });

  // 4 — Email (solo emails válidos con @)
  agrupar(clientes, c => {
    const e = String(c.email || '').toLowerCase().trim();
    return e.includes('@') ? e : null;
  }).forEach(([email, grupo]) =>
    duplicadosEmail.push({ tipo: 'Email duplicado', valor: email, clientes_afectados: grupo.map(resumir) })
  );

  return res.json({
    total_alertas: duplicadosRFC.length + duplicadosCURP.length + duplicadosNomFecha.length + duplicadosEmail.length + alertasImpers.length,
    duplicados_rfc:           duplicadosRFC,
    duplicados_curp:          duplicadosCURP,
    duplicados_nombre_fecha:  duplicadosNomFecha,
    duplicados_email:         duplicadosEmail,
    alertas_impersonamiento:  alertasImpers,
    resumen: {
      rfc:             duplicadosRFC.length,
      curp:            duplicadosCURP.length,
      nombre:          duplicadosNomFecha.length,
      email:           duplicadosEmail.length,
      impersonamiento: alertasImpers.length,
    },
  });
});

/**
 * POST /api/validar-todos
 * Validación masiva: RENAPO + RFC para cada cliente.
 * Rate limiting: 500ms entre consultas a RENAPO.
 */
app.post('/api/validar-todos', async (req, res) => {
  const { clientes } = req.body;
  if (!Array.isArray(clientes) || !clientes.length) {
    return res.status(400).json({ error: 'Se requiere un array de clientes' });
  }

  const resultados    = [];
  let validadosRenapo = 0;
  let erroresRenapo   = 0;

  for (const c of clientes) {
    const r = {
      id_cliente:           c.id,
      curp_existe_renapo:   false,
      curp_datos_coinciden: false,
      discrepancias_curp:   [],
      rfc_valido:           false,
      rfc_coincide:         false,
      rfc_generado:         null,
      nivel_alerta:         'ok',
      error_renapo:         null,
    };

    // ── Validar RFC ──
    try {
      const apArr = String(c.apellido || '').split(' ');
      const apPat = apArr[0] || '';
      const apMat = apArr.slice(1).join(' ');
      const base  = generarRFCBase(c.nombre, apPat, apMat, c.fecha_nacimiento);
      if (base) {
        r.rfc_generado = base + calcularHomoclave(apPat, apMat, c.nombre);
        if (c.rfc) {
          const reg = String(c.rfc).toUpperCase().trim();
          if (reg === r.rfc_generado)              { r.rfc_valido = true; r.rfc_coincide = true; }
          else if (reg.slice(0,10) === r.rfc_generado.slice(0,10)) { r.rfc_valido = true; r.rfc_coincide = 'parcial'; }
          else { r.rfc_valido = false; r.rfc_coincide = false; r.discrepancias_curp.push('RFC no coincide con datos personales'); }
        }
      }
    } catch { /* silenciar */ }

    // ── Validar CURP vs RENAPO ──
    const curp = String(c.curp || '').trim().toUpperCase();
    if (CURP_REGEX.test(curp)) {
      try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), 10_000);
        const resp = await fetch(
          `https://consultas.curp.gob.mx/CurpSP/rest/consultaCurp/${curp}`,
          { signal: ctrl.signal, headers: { 'Accept': 'application/json' } }
        );
        clearTimeout(tid);

        if (resp.ok) {
          const datos = await resp.json();
          if (datos && (datos.nombre || datos.primerApellido)) {
            r.curp_existe_renapo = true;
            validadosRenapo++;
            // Comparar datos de identidad
            const nomRenapo = normStr(datos.nombre || '');
            const nomBase   = normStr(c.nombre);
            const apRenapo  = normStr(`${datos.primerApellido || ''} ${datos.segundoApellido || ''}`);
            const apBase    = normStr(c.apellido || '');
            if (nomRenapo && nomBase && !nomRenapo.includes(nomBase) && !nomBase.includes(nomRenapo)) {
              r.discrepancias_curp.push('Nombre difiere de RENAPO');
            }
            if (apRenapo && apBase && !apRenapo.includes(apBase.split(' ')[0])) {
              r.discrepancias_curp.push('Apellido difiere de RENAPO');
            }
            r.curp_datos_coinciden = r.discrepancias_curp.length === 0;
          } else {
            erroresRenapo++;
          }
        } else {
          r.error_renapo = 'CURP no encontrada en RENAPO';
          erroresRenapo++;
        }
      } catch (err) {
        r.error_renapo = err.name === 'AbortError' ? 'Timeout RENAPO' : `Error de red: ${err.message}`;
        erroresRenapo++;
      }
      // Rate limiting: máximo 2 consultas por segundo
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    // ── Nivel de alerta ──
    const sinCurpRenapo = CURP_REGEX.test(curp) && !r.curp_existe_renapo && !r.error_renapo;
    if (sinCurpRenapo || r.discrepancias_curp.length >= 2) r.nivel_alerta = 'alto';
    else if (r.discrepancias_curp.length === 1 || !r.rfc_valido || r.error_renapo) r.nivel_alerta = 'medio';
    else if (!CURP_REGEX.test(curp)) r.nivel_alerta = 'bajo';
    else r.nivel_alerta = 'ok';

    resultados.push(r);
  }

  validacionResultados = {
    timestamp:        timestampMexico(),
    total_procesados: clientes.length,
    validados_renapo: validadosRenapo,
    errores_renapo:   erroresRenapo,
    resultados,
  };

  return res.json(validacionResultados);
});

/** GET /api/validar-todos/resultados — Devuelve el último resultado de validación masiva */
app.get('/api/validar-todos/resultados', (req, res) => {
  if (!validacionResultados) {
    return res.json({ sin_resultados: true, mensaje: 'No se ha ejecutado ninguna validación masiva aún' });
  }
  return res.json(validacionResultados);
});

/* ================================================================
   RUTA: GET /api/health
   ================================================================ */
app.get('/api/health', (req, res) => {
  return res.json({ status: 'ok', timestamp: timestampMexico(), total_logs: auditLog.length });
});

/* ================================================================
   ARRANQUE DEL SERVIDOR
   ================================================================ */
async function iniciar() {
  try {
    await verifyConnection();
  } catch (err) {
    console.warn(`[SMTP] Advertencia: ${err.message}`);
    console.warn('[SMTP] El servidor arranca sin verificación SMTP activa.');
  }

  app.listen(PORT, () => {
    console.log(`\n╔══════════════════════════════════════════╗`);
    console.log(`║     KYC Risk Monitor — Backend v1.1      ║`);
    console.log(`╠══════════════════════════════════════════╣`);
    console.log(`║  Puerto:    ${String(PORT).padEnd(30)}║`);
    console.log(`║  Banco:     ${String(process.env.BANCO_NOMBRE || '(sin configurar)').padEnd(30)}║`);
    console.log(`╚══════════════════════════════════════════╝\n`);
  });
}

iniciar();
