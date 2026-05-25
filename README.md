# InsightVM Pull Integration

Integración para descargar alertas de InsightVM por estrategia `pull`, con ejecución continua, filtro por severidad, reintentos y logs detallados.

## Inicio rápido

1. Instalar dependencias:

```bash
py -m pip install -r requirements.txt
```

2. Crear archivo de entorno:

```bash
copy .env.example .env
```

3. Editar `.env` con tus credenciales y URL reales de InsightVM.

4. Ejecutar una sola corrida (prueba manual):

```bash
py main.py --env-file .env --once
```

5. Ejecutar en modo continuo (default cada 1 hora):

```bash
py main.py --env-file .env
```

## Dónde ver logs y payloads

- Logs en consola: siempre durante la ejecución.
- Log en archivo (por defecto): `logs/integration.log`.
- Payloads descargados (por defecto): carpeta `payloads/`.
  - `raw_api_YYYYmmdd_HHMMSS.json`
  - `mapped_YYYYmmdd_HHMMSS.json`
  - `filtered_YYYYmmdd_HHMMSS.json`
  - `run_YYYYmmdd_HHMMSS.meta.json`

## Dos formas de datos (raw vs mapeado)

La integración guarda dos vistas de la data:

1. `raw 1:1` (crudo real de API)
- Está en `raw_api_*.json`.
- Es la respuesta original de InsightVM, sin transformación funcional:
  - `assets_pages` -> páginas crudas de `GET /assets`
  - `asset_vulnerabilities` -> respuesta cruda por asset de `GET /assets/{id}/vulnerabilities`
  - `vulnerability_definitions` -> respuesta cruda por vulnerabilidad de `GET /vulnerabilities/{id}`
- Uso: auditoría, troubleshooting y comparación contra mapeo.

2. `mapeado/operativo` (el flujo con el que trabajamos)
- Está en `mapped_*.json`:
  - `assets`
  - `findings`
  - `meta`
- Es la data ya normalizada por nuestra lógica para operación.
- Luego de ese mapeo se genera `filtered_*.json` con severidades configuradas (`ALERT_SEVERITIES`, por defecto `critical,high`).

Resumen práctico:
- `raw_api_*.json` = verdad cruda 1:1 de InsightVM.
- `mapped_*.json` = versión mapeada funcional para trabajar.
- `filtered` = versión final operativa (altas/críticas por defecto).

Puedes cambiar rutas con:
- `LOG_FILE` en `.env` o `--log-file`
- `PAYLOAD_DIR` en `.env` o `--payload-dir`

## Configuración principal

Variables clave en `.env`:

- `INSIGHTVM_BASE_URL`: URL API InsightVM (ejemplo: `https://host:3780/api/3`)
- `INSIGHTVM_USER`: usuario
- `INSIGHTVM_PASSWORD`: contraseña
- `INSIGHTVM_TIMEOUT`: timeout por request (segundos)
- `INSIGHTVM_VERIFY_SSL`: `true` o `false`
- `PULL_INTERVAL_SECONDS`: intervalo entre ciclos (`3600` = 1 hora)
- `PAGE_SIZE`: tamaño de página de API
- `MAX_RETRIES`: reintentos por ciclo
- `RETRY_BACKOFF_SECONDS`: base del backoff exponencial
- `ALERT_SEVERITIES`: severidades permitidas en payload filtrado
- `LOG_LEVEL`: `DEBUG|INFO|WARNING|ERROR`
- `LOG_FILE`: ruta del log
- `PAYLOAD_DIR`: carpeta de salida de payloads

## Ejemplos útiles

Ejecutar cada 30 minutos:

```bash
py main.py --env-file .env --interval-seconds 1800
```

Solo severidades críticas:

```bash
py main.py --env-file .env --severities critical
```

Cambiar carpeta de payloads:

```bash
py main.py --env-file .env --payload-dir C:\tmp\ivm_payloads
```

## Tests

Ejecutar suite:

```bash
py -m pytest -q
```

Con detalle:

```bash
py -m pytest -vv -s --log-cli-level=INFO
```

## Notas

- Al iniciar, la integración muestra un banner ASCII de InsightVM en logs.
- `requirements.txt` se mantiene como instalación rápida tradicional.
