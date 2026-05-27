# InsightVM Pull Integration

Integración para descargar alertas de InsightVM por estrategia `pull`, con snapshot por ejecución, filtros de severidad, reintentos y logs.

## Inicio rápido (lo principal)

1. Crear y activar entorno virtual:

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Instalar dependencias:

```bash
pip install -r requirements.txt
```

3. Configurar variables de entorno:

```bash
cp .env.example .env
nano .env   # editar con tus credenciales
```

4. Ejecutar una sola corrida (snapshot):

```bash
python3 main.py --env-file .env --once
```

5. Ejecutar tests:

```bash
python3 -m pytest -q
```

## Dónde ver resultados

- Logs:
  - Consola (durante ejecución)
  - Archivo: `logs/integration.log`

- Payloads (en `payloads/`):
  - `raw_api_YYYYmmdd_HHMMSS.json` -> data cruda 1:1 desde API InsightVM.
  - `filtered_YYYYmmdd_HHMMSS.json` -> data filtrada por severidad (por defecto `critical,high`).
  - `run_YYYYmmdd_HHMMSS.meta.json` -> metadatos del ciclo (éxito/error, tiempos, conteos).

## Flujo funcional

1. Baja data desde InsightVM (`/assets`, `/assets/{id}/vulnerabilities`, `/vulnerabilities/{id}`).
2. Guarda crudo 1:1 en `raw_api`.
3. Aplica filtro de severidad y guarda resultado operativo en `filtered`.
4. Si `BACKEND_ENABLED=true`, adapta la data filtrada al formato requerido y la envía al backend (`guarda_alarma.php`).
   Solo se envían hallazgos de severidades configuradas en `ALERT_SEVERITIES` (por defecto: `critical,high`).

## Flujo de endpoints InsightVM

```txt
┌────────────────────────────┐
│ 1. GET /assets             │
│ Obtiene equipos            │
│ asset_id + metadata        │
└──────────────┬─────────────┘
               │ usa asset_id
               ▼
┌────────────────────────────────────────────┐
│ 2. GET /assets/{asset_id}/vulnerabilities │
│ Obtiene vulnerabilidades por equipo        │
│ devuelve vulnerability_id                  │
└──────────────┬─────────────────────────────┘
               │ usa vulnerability_id
               ▼
┌──────────────────────────────────────────────┐
│ 3. GET /vulnerabilities/{vulnerability_id}   │
│ Obtiene detalle de vulnerabilidad            │
│ severity, CVSS, risk score, título, etc.     │
└──────────────┬───────────────────────────────┘
               │ normalizar y filtrar
               ▼
┌────────────────────────────┐
│ 4. POST API MiFIbra        │
│ Envía payload Nivel 1      │
│ guarda alerta en BD/NOC    │
└────────────────────────────┘
```

## Ejecución continua

Modo servicio (intervalo por defecto: 1 hora):

```bash
python3 main.py --env-file .env
```

Override de intervalo (ej. 30 min):

```bash
python3 main.py --env-file .env --interval-seconds 1800
```

### Ejecutar en background con nohup

```bash
nohup python3 main.py --env-file .env > /dev/null 2>&1 &
```

### Ejecutar con systemd (recomendado para producción)

Crear el archivo de servicio:

```bash
sudo nano /etc/systemd/system/insightvm-pull.service
```

Contenido:

```ini
[Unit]
Description=InsightVM Pull Integration
After=network.target

[Service]
Type=simple
User=<tu-usuario>
WorkingDirectory=/ruta/al/proyecto/INSIGHT-MIFIBRA-RF1
ExecStart=/ruta/al/proyecto/INSIGHT-MIFIBRA-RF1/venv/bin/python3 main.py --env-file .env
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Habilitar y arrancar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable insightvm-pull
sudo systemctl start insightvm-pull
sudo systemctl status insightvm-pull
```

## Configuración principal (`.env`)

- `INSIGHTVM_BASE_URL`
- `INSIGHTVM_USER`
- `INSIGHTVM_PASSWORD`
- `INSIGHTVM_TIMEOUT`
- `INSIGHTVM_VERIFY_SSL`
- `PULL_INTERVAL_SECONDS`
- `PAGE_SIZE`
- `MAX_RETRIES`
- `RETRY_BACKOFF_SECONDS`
- `ALERT_SEVERITIES`
- `LOG_LEVEL`
- `LOG_FILE`
- `PAYLOAD_DIR`
- `BACKEND_ENABLED` (true/false)
- `BACKEND_URL` (ej: `https://10.208.232.208/txdxsecure/guarda_alarma.php`)
- `BACKEND_LOCAL`
- `BACKEND_ALARM_TYPE`
- `BACKEND_TIMEOUT`
- `BACKEND_VERIFY_SSL`
- `BACKEND_PAYLOAD_LEVEL` (basic/level1 - determina el nivel de detalle enviado)

Referencia completa: [.env.example](.env.example)

## Normalización de Severidad Interna

El script normaliza automáticamente los niveles de severidad devueltos por InsightVM al estándar del backend:
- `Severe` -> `high`
- `Moderate` -> `medium`
- `Informational` -> `info`

## Integración backend (Nivel 1)

El script soporta dos niveles de payload a través de `BACKEND_PAYLOAD_LEVEL`:

### Modo `basic`
Envía únicamente el conjunto básico de 5 campos (útil si el backend aún no acepta campos adicionales):
* `servidor`
* `ip`
* `TipoAlarma`
* `Local`
* `fechaalarma`

### Modo `level1` (Recomendado / Defecto)
Envía los campos básicos junto al estándar del **Nivel 1**:
* `estado` (por defecto `0`)
* `asset_id`
* `vulnerability_id`
* `vulnerability_title`
* `severity`
* `cvss_score`
* `source` (fijo `"InsightVM"`)

> [!NOTE]
> **El Nivel 1 no incluye soluciones (`solution`).** Toda la información de remedición y soluciones queda explícitamente reservada para el estándar del **Nivel 2**.

Respuestas que maneja:
- Éxito: `{"success": true}`
- Error de campos: `{"success": false, "message": "Campos requeridos faltantes: ..."}`
- Conflicto: `{"success": false, "message": "Ya existe un registro activo ..."}`
- Error BD/general: `{"success": false, "message": "Error en la base de datos"}`

El detalle del envío se registra en `run_*.meta.json` bajo la clave `backend`:
- `sent_ok`
- `conflicts`
- `validation_errors`
- `backend_errors`
