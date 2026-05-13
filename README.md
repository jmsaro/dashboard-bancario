# Dashboard Bancario — Actinver

Plataforma de demos y herramientas para proyectos del sector financiero mexicano.

## Módulos disponibles

| Archivo | Descripción |
|---|---|
| `index.html` | KYC Risk Monitor + Dashboard de KPIs |
| `dictaminacion.html` | **Plataforma de Dictaminación Legal Inteligente** (RFP Actinver) |

## Plataforma de Dictaminación Legal Inteligente

Demo funcional navegable construida como propuesta técnica para el RFP de Grupo Financiero Actinver.

### Módulos de la demo

1. **Dashboard** — KPIs en tiempo real, semáforo agregado, expedientes recientes, SLAs
2. **Ingesta Documental** — Drag-and-drop de documentos, checklist de 8 documentos PM, integración OpenText
3. **OCR + Extracción NLP** — Vista de documento con campos resaltados, 42 campos extraídos, validaciones cruzadas
4. **Motor de Dictaminación** — Resultado Verde/Amarillo/Rojo, score breakdown, marco normativo
5. **Trazabilidad E2E** — Audit trail completo, cifrado AES-256/TLS, hashes SHA-256
6. **Conectores** — Estado de OpenText, Salesforce, Active Directory, BPM Workflow
7. **APIs & Docs** — Documentación REST interactiva con request/response JSON
8. **Arquitectura** — Diagrama por capas (Presentación → IA → Integración → Infraestructura)
9. **Propuesta Funcional** — Flujo E2E 8 pasos, beneficios cuantificables, roadmap 28 semanas

### APIs REST v2

El backend expone los siguientes endpoints:

```
POST   /api/v2/expedientes              Crear expediente
GET    /api/v2/expedientes              Listar expedientes
GET    /api/v2/expedientes/:id          Obtener expediente
PATCH  /api/v2/expedientes/:id          Actualizar expediente
POST   /api/v2/documentos/upload        Cargar documento
POST   /api/v2/documentos/ocr           Procesar OCR + NLP
POST   /api/v2/dictamen/generar         Generar dictamen (motor DictIA)
GET    /api/v2/dictamen/:id             Obtener dictamen
POST   /api/v2/sync/salesforce          Sincronizar con Salesforce
POST   /api/v2/sync/opentext            Sincronizar con OpenText
GET    /api/v2/health                   Health check con estado de integraciones
```

### Ecosistema tecnológico integrado

- **OpenText ECM** — Repositorio documental + OpenText Extreme
- **Salesforce FSC** — CRM + sincronización de oportunidades
- **Active Directory** — SSO/SAML 2.0 + MFA
- **BPM Workflow** — Activiti 7 (onboarding E2E)
- **Firma electrónica** — NOM-151 / FIEL / e.firma

### Seguridad

- Cifrado en reposo: AES-256-GCM + HSM
- Cifrado en tránsito: TLS 1.3 + mTLS
- Autenticación: OAuth 2.0 + JWT + SAML 2.0
- Auditoría: SIEM inmutable, retención 10 años

## Instalación y ejecución

```bash
npm install
cp .env.example .env   # configurar variables
npm start              # puerto 3000
```

Abrir en navegador:
- `http://localhost:3000/` — KYC Dashboard
- `http://localhost:3000/dictaminacion.html` — Dictaminación Legal
