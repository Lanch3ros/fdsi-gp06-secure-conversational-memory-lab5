# Seguridad del proyecto — evidencia del laboratorio

Lab. No. 05 (FDSI): seguridad en el ciclo de desarrollo. Este registro cubre los
puntos 1 a 4 del enunciado (alcance, controles nativos, SAST + secretos y SCA). Los
puntos 5 a 8 (DAST, validación manual, corrección y presentación) siguen pendientes.

## 1. Alcance autorizado
- Repositorio: https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5 (público, cuenta personal)
- Rama evaluada y commit de línea base: `main` / `6291230868533ff5c4a99ba0895638ab97079e39`
- Rama del laboratorio: `security/lab-fsi`
- URL de staging propio (si aplica): no hay. El proyecto no expone servicio web (ver abajo); el DAST del punto 5 queda por definir.
- Responsables: Isaac David Burgos Cervantes · Jose Luis Lancheros Aroya · Gina Sofía García Zapata (FDSI-GP-06).
- Autorización: repositorio y entorno propios del equipo, 21/10/2026.
- Fuera de alcance: producción, sistemas de terceros, datos reales y pruebas destructivas.

**Tecnología.** Python 3.11, gestionado con `uv`. Dependencias directas: `pydantic`,
`chromadb` (índice vectorial embebido, `PersistentClient` en disco), `httpx`; de
desarrollo, `pytest` y `freezegun`. Modelo Llama 3.1 8B en Ollama local. Imagen
Docker opcional (`Dockerfile`, `docker-compose.yml`).

**Flujos de autenticación y APIs.** No hay autenticación: la interfaz es la CLI
`memlab` y el usuario se pasa como argumento (`--user A`). No hay API HTTP propia.
La única llamada de red es `httpx` contra Ollama en `http://localhost:11434`, sin
credenciales.

**Activos.**
- Almacén de memoria: SQLite (`data/memory.sqlite3`), índice ChromaDB (`data/chroma/`) y caché de sesión.
- Clave HMAC `MEMLAB_HMAC_KEY` (C4 firmas de procedencia, C5 prueba de borrado).
- Evidencia del experimento (`evidence/runs/`), de la que salen todas las métricas.

**Riesgo principal.** Pérdida de aislamiento entre usuarios e instrucciones
persistentes en la memoria de largo plazo (confidencialidad e integridad): es
justamente lo que el laboratorio estudia en el perfil `unsecure`. En el código, el
riesgo de seguridad de software más relevante es la integridad de las firmas de
C4/C5, que depende de que la clave HMAC no sea la de desarrollo (F-05).

## 2. Línea base y herramientas
| Herramienta | Tipo | Fecha | Resultado | Enlace a evidencia |
|---|---|---|---|---|
| Semgrep 1.182.0 (`p/owasp-top-ten` + `p/secrets`) | SAST | 21/10/2026 | Actions, PR #1: 115 archivos, 17 hallazgos (1 ERROR, 2 MEDIUM, 14 WARNING), 0 errores de análisis. Triage en la sección 3. | [Run 39690739269](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/39690739269) · [`resultado-semgrep.zip`](lab5/evidencia/actions-pr1/resultado-semgrep.zip) |
| CodeQL 2.27.3, Default setup (Python) | SAST | 21/10/2026 y 02/11/2026 | Suite `default`, amenazas `remote`: 43 reglas y 0 resultados en la línea base `6291230` (21/10) y en el merge del PR #1 `b7117a3` (02/11). Suite `extended`, amenazas `remote_and_local` (desde el 02/11): 50 reglas y 9 alertas `py/path-injection` sobre `b7117a3`; 7 siguen abiertas y 2 se descartaron como falso positivo. Análisis semanal y en cada push a `main`. | [Code scanning](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/security/code-scanning) · capturas [04](lab5/evidencia/capturas/04-code-scanning-default.webp), [05](lab5/evidencia/capturas/05-codeql-tool-status.webp), [06](lab5/evidencia/capturas/06-code-scanning-extended.webp), [07](lab5/evidencia/capturas/07-codeql-config-extended.webp) y [08](lab5/evidencia/capturas/08-codeql-alerta-6-falso-positivo.webp) |
| Gitleaks (gitleaks-action v3) | Secretos | 21/10/2026 | Actions, PR #1: "No leaks detected" sobre todo el historial (`fetch-depth: 0`). También en verde en el push a `main` del 02/11/2026. | [Run 39690739269](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/39690739269) · [captura](lab5/evidencia/capturas/01-actions-pr1.webp) |
| GitHub Secret Protection + push protection | Secretos | 21/10/2026 | Activados (API y captura) | [captura 03](lab5/evidencia/capturas/03-settings-ai-secret-protection.webp) |
| Dependabot alerts | SCA | 21/10/2026 y 02/11/2026 | 0 alertas en la línea base. Desde el merge del PR #1 (02/11): 8 alertas abiertas, todas sobre los archivos de evidencia `docs/lab5/evidencia/requirements-*.txt` y ninguna sobre `pyproject.toml`: 7 de `chromadb` (4 CVE distintos) y 1 de `pytest` (CVE-2025-71176), que originó el PR #2. Triage en la sección 3. | [Dependabot](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/security/dependabot) · [captura 09](lab5/evidencia/capturas/09-dependabot-alertas.webp) |
| pip-audit (2.10.1 en local) | SCA | 21/10/2026 | Local, versiones mínimas: 5 entradas en 2 paquetes: 3 CVE de `chromadb` 0.5.0 y 1 de `pytest` 8.0.0 (PYSEC-2026-1845 sale dos veces). Local y Actions (PR #1), últimas versiones: 88 paquetes y 5 entradas, todas de `chromadb` 1.5.9 (4 CVE distintos; PYSEC-2026-311 sale dos veces). La resolución de Actions coincide paquete por paquete con la local. | [`docs/lab5/evidencia/`](lab5/evidencia/) · [`resultado-pip-audit.zip`](lab5/evidencia/actions-pr1/resultado-pip-audit.zip) |
| OWASP ZAP Baseline | DAST pasivo | — | Pendiente (punto 5) | — |

**Controles nativos de GitHub (punto 2).** Estado en Settings → Advanced Security
el 02/11/2026 ([captura 02](lab5/evidencia/capturas/02-settings-dependabot-codeql.webp),
[captura 03](lab5/evidencia/capturas/03-settings-ai-secret-protection.webp)):
- Dependabot alerts y Dependabot security updates: activados. Las security updates
  abrieron el PR #2.
- Dependabot version updates, grouped security updates y malware alerts:
  apagados. Por eso `.github/dependabot.yml` aparece como *Disabled*: hoy no abre
  PR de versiones.
- CodeQL analysis en Default setup, con Copilot Autofix activado.
- Secret Protection y push protection: activados.
- Los checks de code scanning fallan con alertas de seguridad `high` o mayores, pero
  `main` no tiene ruleset ni protección de rama, así que un check fallido no
  bloquea el merge.

**Evidencia de Actions.** La ejecución de referencia es la del PR #1 (run
39690739269, commit `145b8f8`, 21/10/2026), con los tres jobs en verde. Los
artefactos se guardan sin modificar en
[`docs/lab5/evidencia/actions-pr1/`](lab5/evidencia/actions-pr1/), y su SHA-256
coincide con el `digest` que publica la API de GitHub para cada artefacto:

- `resultado-semgrep.zip`: `7e57b1cea3ee4e1ab5246dbbaace32123ec2bfd21a3d332a48b8c21a0010ca03`
- `resultado-pip-audit.zip`: `db37c81f3b8fed5f0851ab33ffe489492306f21b42a2c87fc1b35230f0fe9313`

El verde de Semgrep y pip-audit no significa que no haya hallazgos: esos pasos
terminan en `|| true` y nunca fallan. El de Gitleaks sí falla si encuentra un secreto.

**CodeQL: configuración por defecto y extendida.**
- Con la suite `default` y amenazas `remote`, CodeQL dio 0 alertas, y eso no
  significaba que el código fuera seguro. Con ese modelo, las consultas de flujo
  de datos solo parten de entrada remota, como las peticiones a un servidor web, y
  `memlab` no es un servidor: su entrada son argumentos de la CLI, variables de
  entorno y archivos locales, que CodeQL clasifica como fuentes `local`.
- Al pasar a la suite `extended` con amenazas `remote_and_local` (02/11/2026), el
  mismo commit `b7117a3` dio 9 alertas `py/path-injection`, todas con origen en los
  argumentos de línea de comandos de los scripts de `experiments/`. CodeQL las
  califica `high`; en este proyecto el riesgo es bajo (triage en la sección 3).
- La página de estado de CodeQL muestra "GitHub Actions: 1/1 file scanned"
  ([captura 05](lab5/evidencia/capturas/05-codeql-tool-status.webp)), pero en la
  configuración el lenguaje GitHub Actions está sin marcar
  ([captura 07](lab5/evidencia/capturas/07-codeql-config-extended.webp)): la API
  devuelve `languages: ["python"]`, los análisis registrados son solo de Python y
  ninguna alerta de CodeQL toca los workflows. F-02 y F-06 solo los detecta Semgrep.
- Ni CodeQL ni Semgrep señalaron `src/memlab/memory/retriever.py`, donde el perfil
  Unsecure recupera memorias sin filtrar por usuario. Es una falla de lógica de
  autorización: el laboratorio la mide con T02, no con SAST.

**Dependabot: de 0 a 8 alertas.**
- En la línea base Dependabot no dio alertas. El grafo de dependencias de GitHub
  lee `pyproject.toml`, pero registra sus 5 dependencias sin versión (consulta
  `dependencyGraphManifests` del 02/11/2026): el proyecto declara rangos
  (`chromadb>=0.5.0`) y no versiona un archivo de bloqueo. Para compensarlo, el job
  `sca` resuelve las dependencias con `uv pip compile` y las audita con `pip-audit`
  en los dos extremos del rango: las versiones **mínimas** que permite
  `pyproject.toml` y las **últimas** que instala hoy `make setup`.
- Esas dos resoluciones se guardaron como evidencia, con versiones fijas, en
  `docs/lab5/evidencia/requirements-minimas.txt` y `requirements-ultimas.txt`.
  GitHub las toma como manifiestos, y al fusionar el PR #1 (02/11) Dependabot abrió
  8 alertas sobre ellas ([captura 09](lab5/evidencia/capturas/09-dependabot-alertas.webp)).
  Coinciden una a una con `pip-audit`: en la resolución mínima, 3 avisos de
  `chromadb` 0.5.0 y el de `pytest` 8.0.0; en la última, los 4 avisos de
  `chromadb` 1.5.9. CVE-2026-45829 solo afecta desde la 1.0.0, y por eso ninguna
  de las dos herramientas lo reporta en la 0.5.0.
- Las *security updates* de Dependabot abrieron el PR #2 contra esos dos archivos
  de evidencia (análisis en la sección 3).

## 3. Hallazgos y gestión
| ID | Categoría | Descripción sin secretos | Riesgo | Archivo/ruta | Cambio propuesto | Estado |
|---|---|---|---|---|---|---|
| F-01 | SAST · CWE-250 | El contenedor corre como `root`: el `Dockerfile` no define `USER` (Semgrep `dockerfile.security.missing-user`). | Medio | `Dockerfile:16` | Crear un usuario sin privilegios y añadir `USER` antes de `CMD`. | Abierto |
| F-02 | SAST · CWE-1357 | Las acciones de GitHub se referencian por etiqueta mutable (`@v4`, `@v5`, `@v3`), no por SHA (Semgrep `github-actions-mutable-action-tag`). | Bajo | `.github/workflows/seguridad-estatica.yml` | Fijar cada acción a su SHA; Dependabot (`github-actions`) las mantiene al día. | Abierto |
| F-03 | SCA · CVE-2026-45829/45830/45831/45833 | `chromadb` tiene ejecución de código y falta de aislamiento entre tenants **en su servidor HTTP**. Tres avisos afectan a todo el rango `>=0.5.0`, y CVE-2026-45829 desde la 1.0.0. Sin versión corregida (Dependabot #2 a #8). | No aplica | `pyproject.toml` | Ninguno inmediato: ver análisis abajo. Vigilar el aviso. | Aceptado |
| F-04 | SCA · CVE-2025-71176 | `pytest` ≤ 9.0.2 usa `/tmp/pytest-of-{usuario}` de forma insegura en UNIX. El rango `pytest>=8.0` lo permite (Dependabot #1). | Bajo | `pyproject.toml` (extra `dev`) | Subir el piso a `pytest>=9.0.3`. No fusionar el PR #2 de Dependabot (ver análisis abajo). | Abierto |
| F-05 | Revisión manual · CWE-798 | Clave HMAC de desarrollo fija en el código; se usa en silencio si no se exporta `MEMLAB_HMAC_KEY`. Semgrep `p/secrets` no la detectó. | Medio | `src/memlab/config.py:37` | Exigir la variable en corridas oficiales (fallar si falta) o dejar constancia en el manifiesto. | Abierto |
| F-06 | SAST · CWE-829 | `dependabot.yml` no define `cooldown`: Dependabot propone una versión el mismo día en que se publica, sin margen para detectar un paquete comprometido (Semgrep `dependabot-missing-cooldown`). Lo introdujo el `dependabot.yml` agregado en este laboratorio. Hoy no tiene efecto práctico: `cooldown` solo aplica a las actualizaciones de versión, que están apagadas. | Bajo | `.github/dependabot.yml:5` y `:11` | Añadir `cooldown` con `default-days: 7` a cada ecosistema. | Abierto |
| F-07 | SAST (CodeQL) · CWE-22 | `compute_metrics.py <corrida>` no valida el nombre de la corrida: con `../` lee `results.json` y `manifest.json` y escribe `<corrida>.json` fuera de `evidence/` (alertas #2, #8 y #9, `py/path-injection`). | Bajo | `experiments/compute_metrics.py:178-180` y `:191` | Aceptar solo nombres de carpetas que estén directamente en `evidence/runs/`. | Abierto |
| F-08 | SAST (CodeQL) · CWE-22 | `run_t02.py`, `run_t04.py` y `run_t05.py` usan `--profile` para crear la carpeta de la corrida y vaciar su `data/` (`shutil.rmtree`) antes de validarlo con `Profile(...)`. `run_t01.py` sí valida primero (alertas #1, #3, #4 y #5, `py/path-injection`). | Bajo | `experiments/_common.py:30` y `:60-62`, desde `run_t02.py:45-47`, `run_t04.py:46-48` y `run_t05.py:67-69` | Validar el perfil antes de usarlo, como `run_t01.py`, o con `choices` en `argparse`, como `cli.py`. | Abierto |

### Triage de Semgrep (punto 3)

Los 17 hallazgos de Actions (PR #1) salen de tres reglas:

| Regla | Severidad Semgrep | Ocurrencias | Veredicto |
|---|---|---|---|
| `dockerfile.security.missing-user` | ERROR | 1 (`Dockerfile:16`) | Verdadero positivo → F-01 |
| `github-actions-mutable-action-tag` | WARNING | 8 en `.github/workflows/seguridad-estatica.yml` | Verdadero positivo, riesgo bajo → F-02 |
| `github-actions-mutable-action-tag` | WARNING | 6 en `Kit_Integracion_AppSec_GitHub_FSI/.github/workflows/` | **Falsa alarma** en la práctica |
| `dependabot-missing-cooldown` | MEDIUM | 2 en `.github/dependabot.yml` | Verdadero positivo, riesgo bajo → F-06 |

- **F-01 es real.** Sin `USER`, `memlab` corre como `root` dentro del contenedor, y
  `docker-compose.yml` monta `./evidence` con permiso de escritura: un fallo en el
  proceso tendría privilegios de `root` sobre el contenedor y sobre esa carpeta. El
  impacto es acotado porque el contenedor solo se usa en local, pero el arreglo es
  pequeño.
- **Las 6 ocurrencias del kit son falsas alarmas.** GitHub Actions solo ejecuta los
  workflows de `.github/workflows/` en la raíz del repositorio; las copias dentro
  de `Kit_Integracion_AppSec_GitHub_FSI/` son material de referencia y nunca
  corren. El patrón sí es real donde está activo (F-02), pero en esa ruta no hay
  riesgo. Se pueden excluir del análisis con un `.semgrepignore`.
- La corrida local del 21/10 dio 12 hallazgos y Actions 17. La diferencia son las
  3 acciones del job `sca` y las 2 entradas de `dependabot.yml`, que se agregaron
  después de esa corrida local.

### Triage de CodeQL (suite `extended`, amenazas `remote_and_local`)

Las 9 alertas son de la regla `py/path-injection` (CWE-22), calificadas `high` por
CodeQL. El origen siempre es `parse_args()` de un script de `experiments/`:

| Alertas | Dónde se usa la ruta | Origen | Veredicto |
|---|---|---|---|
| #8, #9 | `compute_metrics.py:179-180`: lee `results.json` y `manifest.json` | argumento `run` de `compute_metrics.py` | Verdadero positivo, riesgo bajo → F-07 |
| #2 | `_common.py:35`: `write_json` | `compute_metrics.py` y los cuatro runners | Verdadero positivo por `compute_metrics.py` → F-07 |
| #1, #3, #4, #5 | `_common.py:30` (`mkdir`) y `:60-62` (`rmtree` y `mkdir` de `data/`) | `--profile` de `run_t01`, `t02`, `t04` y `t05` | Verdadero positivo por `t02`, `t04` y `t05` → F-08 |
| #6, #7 | `audit.py:24` y `:35`: log de auditoría | `--profile` de los cuatro runners | **Falso positivo** |

- **#6 y #7 son falsos positivos.** Los cuatro runners crean el `AuditLog` después
  de `Profile(args.profile)`, que solo acepta `unsecure` o `secure` y detiene la
  ejecución con cualquier otro valor. CodeQL no reconoce esa conversión al `Enum`
  como validación. Se descartaron en GitHub como *False positive* el 02/11/2026
  ([captura 08](lab5/evidencia/capturas/08-codeql-alerta-6-falso-positivo.webp)).
- **El riesgo real de F-07 y F-08 es bajo.** Para explotarlos hay que controlar los
  argumentos o el entorno (`MEMLAB_PROFILE`) de quien corre el experimento, y esa
  persona ya tiene los mismos permisos. `make metrics` usa `--all`, que toma los
  nombres de `evidence/runs/` y no de la línea de comandos. El efecto más probable
  es un error de tipeo: `make t02 PROFILE=secur` deja en `evidence/runs/` una
  carpeta sin resultados antes de fallar.
- F-07 y F-08 son candidatos a la corrección del punto 7: el arreglo es pequeño, no
  cambia los resultados de las corridas válidas y CodeQL puede confirmar el cierre
  de las alertas al reanalizar. Sus siete alertas siguen abiertas
  ([captura 06](lab5/evidencia/capturas/06-code-scanning-extended.webp) muestra las
  9 antes del triage).

### Análisis SCA (punto 4)

**Dependencia seleccionada: `chromadb`.**
- Versión: dependencia directa de ejecución con rango `>=0.5.0`. La resolución
  mínima instala la 0.5.0 y la última, la 1.5.9. Ninguno de los cuatro avisos
  tiene versión corregida:

| Aviso | Severidad (GitHub) | Versiones afectadas | Qué permite | Alertas |
|---|---|---|---|---|
| CVE-2026-45829 · GHSA-f4j7-r4q5-qw2c | Crítica | 1.0.0 a 1.5.9 | Ejecutar código en el servidor **sin autenticarse**, enviando un repositorio de modelo malicioso con `trust_remote_code` en `true` al endpoint `/api/v2/tenants/{tenant}/databases/{db}/collections` | #5 |
| CVE-2026-45833 · GHSA-36p7-vc44-83pf | Crítica | 0.4.17 a 1.5.9 | Lo mismo en `.../collections/{collection_id}`, para un usuario autenticado con permiso `UPDATE_COLLECTION` | #4 y #8 |
| CVE-2026-45830 · GHSA-2wm9-hf6c-p5cr | Alta | 0.4.17 a 1.5.9 | Que cualquier usuario autenticado lea, escriba o borre datos en colecciones de cualquier tenant | #2 y #6 |
| CVE-2026-45831 · GHSA-xph7-9rjv-w5fr | Alta | 0.5.0 a 1.5.9 | Que `SimpleRBACAuthorizationProvider` conceda un permiso sin comprobar a qué tenant, base de datos o colección aplica | #3 y #7 |

- ¿Aplica al código? **No es explotable en este proyecto.** Los cuatro avisos son
  del servidor HTTP de ChromaDB: sus endpoints, su autenticación y su RBAC. El
  laboratorio usa el cliente embebido
  `chromadb.PersistentClient(path=...)` (`src/memlab/memory/store.py:51`): no
  levanta servidor, no abre puertos, no configura autenticación ni RBAC y no
  carga funciones de embedding remotas con `trust_remote_code` (usa la
  compilación ONNX por defecto de all-MiniLM-L6-v2).
- Alcance: si en el futuro se desplegara ChromaDB como servicio (por ejemplo, otro
  contenedor en `docker-compose.yml`), los avisos pasarían a aplicar.
- Medida correctiva: no actualizar ni cambiar de versión (no hay corrección, y
  cambiar `chromadb` alteraría las corridas oficiales del laboratorio). Mantener el
  cliente embebido, no exponer ChromaDB por red y revisar el aviso con Dependabot y
  el job `sca`.
- Decisión en Dependabot: descartar las alertas #2 a #8 como *Vulnerable code is not
  actually used*, con esta justificación.
- Observación: CVE-2026-45830/45831 (falta de aislamiento entre tenants) es el
  mismo tipo de falla que el control C1 corrige en la capa de recuperación. Aquí no
  depende del RBAC de ChromaDB: en el perfil `secure`, el filtro por
  `tenant_id`/`user_id` lo aplica el propio `retriever.py` en cada consulta.

**Dependencia secundaria: `pytest`.**
- Versión: el piso `>=8.0` permite versiones vulnerables (8.0.0 en la resolución
  mínima); `make setup` instala hoy `9.1.1`, que no es vulnerable. Aviso
  CVE-2025-71176 · GHSA-6w46-j5rx-g56g, severidad media, corregido en la 9.0.3.
- Alcance: solo desarrollo (extra `dev` de `pyproject.toml`). Dependabot lo marca
  `runtime` porque lee la resolución aplanada, que no distingue extras.
- ¿Aplica? Solo en desarrollo y en equipos UNIX compartidos. Los tests usan
  `tmp_path` (`tests/conftest.py:19`). En macOS el directorio temporal es por
  usuario (`$TMPDIR`) y el runner de Actions es efímero y de un solo usuario, así
  que el riesgo práctico es bajo.
- Medida correctiva: subir el piso a `pytest>=9.0.3`. Es compatible, porque la
  resolución actual ya usa la 9.1.1. Es candidato a la remediación del punto 7.
  La alerta #1 queda abierta mientras tanto. Está sobre el archivo de evidencia, así
  que subir el piso no basta para cerrarla: hay que regenerar la resolución mínima
  al reescanear.
- **El PR #2 de Dependabot no se fusiona.** Se titula *bump pytest from 8.0.0 to
  9.0.3*, pero no toca `pyproject.toml`, que es lo que define qué se instala: cambia
  los dos archivos de evidencia. Además, en `requirements-ultimas.txt` **baja**
  `pytest` de 9.1.1 a 9.0.3. Fusionarlo alteraría la evidencia de la auditoría sin
  corregir nada. Es un ejemplo concreto de por qué no se actualiza a ciegas: el
  título del PR no describe todo lo que cambia.

## 4. Validación antes y después
- Evidencia inicial (captura o artefacto): Actions del PR #1 (run 39690739269), corridas locales del 21/10/2026 (ver sección 2) y, del 02/11/2026, las 9 alertas de CodeQL ([captura 06](lab5/evidencia/capturas/06-code-scanning-extended.webp)) y las 8 de Dependabot ([captura 09](lab5/evidencia/capturas/09-dependabot-alertas.webp)).
- Pull request con corrección: pendiente (punto 7).
- Evidencia de reescaneo: pendiente.
- Riesgo residual y decisión: pendiente.

## 5. Pentest autorizado
- Hipótesis: pendiente (punto 6).
- Entorno de pruebas aislado:
- Solicitudes inocuas y respuestas observadas (sin datos personales):
- Resultado: validado / no reproducible / requiere revisión
- Recomendación y prueba de regresión:
