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
py -m insightvm_pull.cli --env-file .env --once
```

5. Ejecutar en modo continuo (default cada 1 hora):

```bash
py -m insightvm_pull.cli --env-file .env
```

## Dónde ver logs y payloads

- Logs en consola: siempre durante la ejecución.
- Log en archivo (por defecto): `logs/integration.log`.
- Payloads descargados (por defecto): carpeta `payloads/`.
  - `raw_YYYYmmdd_HHMMSS.json`
  - `filtered_YYYYmmdd_HHMMSS.json`
  - `run_YYYYmmdd_HHMMSS.meta.json`

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
py -m insightvm_pull.cli --env-file .env --interval-seconds 1800
```

Solo severidades críticas:

```bash
py -m insightvm_pull.cli --env-file .env --severities critical
```

Cambiar carpeta de payloads:

```bash
py -m insightvm_pull.cli --env-file .env --payload-dir C:\tmp\ivm_payloads
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
- `pyproject.toml` se mantiene porque define el proyecto y el comando CLI de forma estándar moderna.
- `requirements.txt` también se mantiene para instalación rápida tradicional.

