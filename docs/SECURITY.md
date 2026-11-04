# Seguridad del proyecto — evidencia del laboratorio

Lab. No. 05 (FDSI): seguridad en el ciclo de desarrollo. Este registro cubre los
puntos 1 a 7 del enunciado (alcance, controles nativos, SAST + secretos, SCA, DAST
pasivo, validación manual y corrección con reescaneo). El punto 8 (presentación)
sigue pendiente.

## 1. Alcance autorizado
- Repositorio: https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5 (público, cuenta personal)
- Rama evaluada y commit de línea base: `main` / `6291230868533ff5c4a99ba0895638ab97079e39`
- Rama del laboratorio: `security/lab-fsi`
- URL de staging propio (si aplica): no hay. El proyecto no expone servicio web (ver abajo). Para el DAST del punto 5 se usó la alternativa local que permite el enunciado: ZAP Baseline con Docker contra la API de Ollama del laboratorio en `localhost:11434` (sección 3).
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
| Semgrep 1.182.0 y 1.183.0 (`p/owasp-top-ten` + `p/secrets`) | SAST | 21/10/2026 y 03/11/2026 | Actions, PR #1: 115 archivos, 17 hallazgos (1 ERROR, 2 MEDIUM, 14 WARNING), 0 errores de análisis. Antes y después de la corrección del punto 7 (`main` en `939f78d` y en `a881b53`): 22 hallazgos con la misma distribución y ninguno en `experiments/` ni en `tests/`. Los 5 nuevos frente al PR #1 son enlaces HTTP del informe de ZAP. Triage en la sección 3. | [Run 39690739269](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/39690739269) · [`resultado-semgrep.zip`](lab5/evidencia/actions-pr1/resultado-semgrep.zip) · runs [41737876034](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/41737876034) y [41742766519](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/41742766519) |
| CodeQL 2.27.3 y 2.27.4, Default setup (Python; también GitHub Actions desde el 03/11) | SAST | 21/10/2026 a 03/11/2026 | Suite `default`, amenazas `remote`: 43 reglas y 0 resultados en la línea base `6291230` (21/10) y en el merge del PR #1 `b7117a3` (02/11). Suite `extended`, amenazas `remote_and_local` (desde el 02/11): 50 reglas y 9 alertas `py/path-injection` sobre `b7117a3`, de las que 2 se descartaron como falso positivo. Tras la corrección del punto 7 (`a881b53`, 03/11): 0 resultados de Python, y las otras 7 pasaron a *Fixed*. El análisis de GitHub Actions abrió la alerta #10 (`actions/unpinned-tag`, F-02). Análisis semanal y en cada push a `main`. | [Code scanning](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/security/code-scanning) · capturas [04](lab5/evidencia/capturas/04-code-scanning-default.webp), [05](lab5/evidencia/capturas/05-codeql-tool-status.webp), [06](lab5/evidencia/capturas/06-code-scanning-extended.webp), [07](lab5/evidencia/capturas/07-codeql-config-extended.webp) y [08](lab5/evidencia/capturas/08-codeql-alerta-6-falso-positivo.webp) |
| Gitleaks (gitleaks-action v3) | Secretos | 21/10/2026 | Actions, PR #1: "No leaks detected" sobre todo el historial (`fetch-depth: 0`). También en verde en el push a `main` del 02/11/2026. | [Run 39690739269](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/39690739269) · [captura](lab5/evidencia/capturas/01-actions-pr1.webp) |
| GitHub Secret Protection + push protection | Secretos | 21/10/2026 | Activados (API y captura) | [captura 03](lab5/evidencia/capturas/03-settings-ai-secret-protection.webp) |
| Dependabot alerts | SCA | 21/10/2026 y 02/11/2026 | 0 alertas en la línea base. Desde el merge del PR #1 (02/11): 8 alertas, todas sobre los archivos de evidencia `docs/lab5/evidencia/requirements-*.txt` y ninguna sobre `pyproject.toml`: 7 de `chromadb` (4 CVE distintos) y 1 de `pytest` (CVE-2025-71176), que originó el PR #2. Tras el triage del 02/11, las 7 de `chromadb` quedaron descartadas como *not used* y la de `pytest` sigue abierta (F-04); el PR #2 se cerró sin fusionar. Detalle en la sección 3. | [Dependabot](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/security/dependabot) · capturas [09](lab5/evidencia/capturas/09-dependabot-alertas.webp), [10](lab5/evidencia/capturas/10-dependabot-chromadb-descartadas.webp) y [11](lab5/evidencia/capturas/11-pr2-cerrado.webp) |
| pip-audit (2.10.1 en local) | SCA | 21/10/2026 | Local, versiones mínimas: 5 entradas en 2 paquetes: 3 CVE de `chromadb` 0.5.0 y 1 de `pytest` 8.0.0 (PYSEC-2026-1845 sale dos veces). Local y Actions (PR #1), últimas versiones: 88 paquetes y 5 entradas, todas de `chromadb` 1.5.9 (4 CVE distintos; PYSEC-2026-311 sale dos veces). La resolución de Actions coincide paquete por paquete con la local. | [`docs/lab5/evidencia/`](lab5/evidencia/) · [`resultado-pip-audit.zip`](lab5/evidencia/actions-pr1/resultado-pip-audit.zip) |
| OWASP ZAP 2.17.0 Baseline (Docker, local) | DAST pasivo | 03/11/2026 | Alternativa local, porque no hay staging: API de Ollama 0.34.2 del laboratorio (`localhost:11434`). 3 URL analizadas, 0 FAIL y 3 WARN: 2 de riesgo bajo y 1 informativa, todas por encabezados HTTP. Las otras 65 reglas pasivas no alertaron. Triage en la sección 3. | [`docs/lab5/evidencia/zap-local/`](lab5/evidencia/zap-local/) |

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
- Hasta el 02/11, CodeQL solo analizaba Python. La página de estado mostraba
  "GitHub Actions: 1/1 file scanned"
  ([captura 05](lab5/evidencia/capturas/05-codeql-tool-status.webp)), pero en la
  configuración el lenguaje GitHub Actions estaba sin marcar
  ([captura 07](lab5/evidencia/capturas/07-codeql-config-extended.webp)) y la API
  devolvía `languages: ["python"]`.
- Desde el 03/11 a la 01:15 UTC, la configuración incluye también `actions`. Ese
  análisis abrió la alerta #10 (`actions/unpinned-tag`, severidad media) por
  `gitleaks/gitleaks-action@v3`, en `.github/workflows/seguridad-estatica.yml:62`:
  es parte de F-02. CodeQL solo marca la acción de terceros, mientras que Semgrep
  marca las 8 etiquetas mutables. F-06 sigue detectándolo solo Semgrep.
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
| F-02 | SAST · CWE-1357 | Las acciones de GitHub se referencian por etiqueta mutable (`@v4`, `@v5`, `@v3`), no por SHA (Semgrep `github-actions-mutable-action-tag`). Desde el 03/11, CodeQL también lo marca, pero solo para `gitleaks/gitleaks-action@v3` (alerta #10, `actions/unpinned-tag`). | Bajo | `.github/workflows/seguridad-estatica.yml` | Fijar cada acción a su SHA; Dependabot (`github-actions`) las mantiene al día. | Abierto |
| F-03 | SCA · CVE-2026-45829/45830/45831/45833 | `chromadb` tiene ejecución de código y falta de aislamiento entre tenants **en su servidor HTTP**. Tres avisos afectan a todo el rango `>=0.5.0`, y CVE-2026-45829 desde la 1.0.0. Sin versión corregida (Dependabot #2 a #8). | No aplica | `pyproject.toml` | Ninguno inmediato: ver análisis abajo. Vigilar el aviso. | Aceptado (en Dependabot, descartadas como *not used*) |
| F-04 | SCA · CVE-2025-71176 | `pytest` ≤ 9.0.2 usa `/tmp/pytest-of-{usuario}` de forma insegura en UNIX. El rango `pytest>=8.0` lo permite (Dependabot #1). | Bajo | `pyproject.toml` (extra `dev`) | Subir el piso a `pytest>=9.0.3`. El PR #2 de Dependabot se cerró sin fusionar (ver análisis abajo). | Abierto |
| F-05 | Revisión manual · CWE-798 | Clave HMAC de desarrollo fija en el código; se usa en silencio si no se exporta `MEMLAB_HMAC_KEY`. Semgrep `p/secrets` no la detectó. | Medio | `src/memlab/config.py:37` | Exigir la variable en corridas oficiales (fallar si falta) o dejar constancia en el manifiesto. | Abierto |
| F-06 | SAST · CWE-829 | `dependabot.yml` no define `cooldown`: Dependabot propone una versión el mismo día en que se publica, sin margen para detectar un paquete comprometido (Semgrep `dependabot-missing-cooldown`). Lo introdujo el `dependabot.yml` agregado en este laboratorio. Hoy no tiene efecto práctico: `cooldown` solo aplica a las actualizaciones de versión, que están apagadas. | Bajo | `.github/dependabot.yml:5` y `:11` | Añadir `cooldown` con `default-days: 7` a cada ecosistema. | Abierto |
| F-07 | SAST (CodeQL) · CWE-22 | `compute_metrics.py <corrida>` no valida el nombre de la corrida: con `../` lee `results.json` y `manifest.json` y escribe `<corrida>.json` fuera de `evidence/` (alertas #2, #8 y #9, `py/path-injection`). | Bajo | `experiments/compute_metrics.py:178-180` y `:191` | Aceptar solo nombres de carpetas que estén directamente en `evidence/runs/`. Hecho con `child_path()` (`experiments/_common.py`), al leer y al escribir; desde F-11 también rechaza enlaces simbólicos. | Corregido (punto 7) |
| F-08 | SAST (CodeQL) · CWE-22 | `run_t02.py`, `run_t04.py` y `run_t05.py` usan `--profile` para crear la carpeta de la corrida y vaciar su `data/` (`shutil.rmtree`) antes de validarlo con `Profile(...)`. `run_t01.py` sí valida primero (alertas #1, #3, #4 y #5, `py/path-injection`). | Bajo | `experiments/_common.py:30` y `:60-62`, desde `run_t02.py:45-47`, `run_t04.py:46-48` y `run_t05.py:67-69` | Validar el perfil antes de usarlo. Hecho en `new_run_dir()` (`experiments/_common.py`), que usan los cuatro runners; `choices` en `argparse` no bastaba, porque no revisa el valor por defecto que viene de `MEMLAB_PROFILE`. | Corregido (punto 7) |
| F-09 | DAST (ZAP) · CWE-693 | La API de Ollama no envía `X-Content-Type-Options` ni `Cross-Origin-Resource-Policy` (reglas 10021 y 90004 de ZAP). | Bajo | `http://localhost:11434/` (Ollama 0.34.2) | Ninguno: es un componente de terceros, escucha solo en loopback y lo consume `httpx`, no un navegador. Si algún día se expusiera, iría detrás de un proxy que agregue encabezados y autenticación. | Aceptado |
| F-10 | Validación manual · CWE-306 | La API de Ollama no exige autenticación: cualquier proceso del equipo, incluidos los contenedores, puede consultarla y usar el modelo (así lo hace `memlab`, sin credenciales). Lo mitigan dos controles validados: escucha solo en `127.0.0.1` y rechaza con 403 los `Origin` de otros sitios. | Bajo | `http://localhost:11434/api/*` (Ollama 0.34.2) | Mantener Ollama en loopback y no ampliar `OLLAMA_ORIGINS`; si se expone, ponerlo detrás de un proxy con autenticación y TLS (ver sección 5). | Aceptado |
| F-11 | Revisión de código (Codex) · CWE-59 | La primera versión de `child_path()` comparaba las rutas solo como texto. Un enlace simbólico dentro de `evidence/runs/` o `evidence/metrics/` que apuntara fuera pasaba la validación, y `compute()` leía o sobrescribía a través de él. Git guarda enlaces simbólicos, así que uno podía llegar en un commit. | Bajo | `experiments/_common.py:38-39` | Resolver los enlaces con `os.path.realpath` antes de comprobar el prefijo. | Corregido (punto 7) |

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
- Desde el punto 5, Actions da 22 hallazgos: los 17 anteriores más 5 de
  `html.security.plaintext-http-link` en `docs/lab5/evidencia/zap-local/zap-report.html`.
  Son **falsas alarmas**: son los enlaces a la URL escaneada
  (`http://host.docker.internal:11434`) dentro del informe de ZAP, que es un
  archivo de evidencia y no una página que se publique.

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
- F-07 y F-08 se corrigieron en el punto 7 (sección 4): el arreglo es pequeño y no
  cambia los resultados de las corridas válidas. Sus siete alertas pasaron a *Fixed*
  cuando CodeQL reanalizó `main` después del merge del PR #6 (03/11, 23:54 UTC).
  La [captura 06](lab5/evidencia/capturas/06-code-scanning-extended.webp) muestra
  las 9 antes del triage.

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
- Decisión en Dependabot: las alertas #2 a #8 se descartaron el 02/11/2026 como
  *Vulnerable code is not actually used*, con esta justificación resumida en el
  comentario ([captura 10](lab5/evidencia/capturas/10-dependabot-chromadb-descartadas.webp)).
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
- **El PR #2 de Dependabot se cerró sin fusionar** (02/11/2026,
  [captura 11](lab5/evidencia/capturas/11-pr2-cerrado.webp)). Se titula *bump
  pytest from 8.0.0 to 9.0.3*, pero no toca `pyproject.toml`, que es lo que define
  qué se instala: cambia los dos archivos de evidencia. Además, en
  `requirements-ultimas.txt` **baja** `pytest` de 9.1.1 a 9.0.3. Fusionarlo habría
  alterado la evidencia de la auditoría sin corregir nada. Es un ejemplo concreto
  de por qué no se actualiza a ciegas: el título del PR no describe todo lo que
  cambia. La justificación quedó en un comentario del PR, y Dependabot respondió
  que no volverá a avisar de esa versión.

### DAST pasivo (punto 5)

**Por qué en localhost.** `memlab` es una herramienta de línea de comandos y no
expone servicio web, así que no hay staging HTTPS que escanear. Para ese caso el
enunciado permite un "baseline local sobre localhost con Docker". La única
superficie HTTP del sistema es la API de Ollama, que `memlab` llama sin
credenciales (`src/memlab/llm.py:34`) en tres rutas: `POST /api/chat`,
`GET /api/tags` y `GET /api/version`. Es la instancia propia del laboratorio, con
datos ficticios.

**Entorno verificado antes del escaneo (03/11/2026).**
- Ollama 0.34.2, arrancado con `ollama serve` y sin `OLLAMA_HOST`. Escucha solo en
  `127.0.0.1:11434` (lo muestran `lsof` y su propio log), así que no es accesible
  desde la red.
- Docker Engine 29.9.2 e imagen `ghcr.io/zaproxy/zaproxy:stable` para arm64 (ZAP
  2.17.0), digest
  `sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`.

**Comando.** Es el del workflow `dast-staging.yml` del kit con otro destino. Desde
el contenedor, el localhost del Mac se alcanza como `host.docker.internal`:

```bash
docker run --rm -v "<carpeta>:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:11434 -m 1 -r zap-report.html -J zap-report.json -I
```

Es pasivo: un recorrido de hasta 1 minuto y reglas pasivas, sin ataques. Corrió de
22:03:02 a 22:03:30 UTC y terminó con código 0. Los informes HTML y JSON, el plan
que ejecutó ZAP (`zap.yaml`) y la salida de consola están en
[`docs/lab5/evidencia/zap-local/`](lab5/evidencia/zap-local/).

| Regla de ZAP | Riesgo (confianza) | Instancias | Veredicto |
|---|---|---|---|
| 10021 X-Content-Type-Options Header Missing | Bajo (media) | `/` | Real, sin impacto práctico → F-09 |
| 90004 Cross-Origin-Resource-Policy Header Missing or Invalid | Bajo (media) | `/` | Real, sin impacto práctico → F-09 |
| 10049 Storable and Cacheable Content | Informativo (media) | `/`, `/robots.txt` y `/sitemap.xml` | No aplica |

- **Los dos encabezados faltan de verdad.** `GET /` devuelve `Ollama is running` en
  texto plano, sin encabezados de seguridad. Pero los dos protegen a un navegador:
  uno evita que adivine el tipo de contenido y el otro limita la carga del recurso
  desde otros orígenes. Aquí la API la consume `memlab` con `httpx`, no un
  navegador, y solo escucha en loopback.
- **10049 no aplica.** Avisa que las respuestas pueden quedar en caché porque no
  traen `Cache-Control`. `/` solo dice que el servicio está activo y las otras dos
  rutas son 404: no hay nada sensible que cachear.

**Limitaciones.**
- El recorrido solo encontró 3 URL: `/` y dos 404. Ninguna página enlaza las rutas
  `/api/*`, así que el baseline no analizó las que usa `memlab`.
- Se escaneó un componente de terceros, no el código de `memlab`. Los riesgos
  principales del proyecto (aislamiento entre usuarios e instrucciones
  persistentes) están en su lógica: los miden T01 y T02, y el SAST revisa el código.
- La API es HTTP sobre loopback; el staging HTTPS del enunciado no aplica.
- La etiqueta `stable` cambia con cada versión de ZAP; por eso se registra el
  digest de la imagen.
- El baseline no comprueba autenticación. Eso se validó a mano en el punto 6
  (sección 5, F-10).

## 4. Validación antes y después
- Evidencia inicial (captura o artefacto): Actions del PR #1 (run 39690739269), corridas locales del 21/10/2026 (ver sección 2) y, del 02/11/2026, las 9 alertas de CodeQL ([captura 06](lab5/evidencia/capturas/06-code-scanning-extended.webp)) y las 8 de Dependabot ([captura 09](lab5/evidencia/capturas/09-dependabot-alertas.webp)). El informe ZAP local del 03/11/2026 es la línea base del DAST ([`zap-local/`](lab5/evidencia/zap-local/)).
- Pull requests con corrección: el
  [#6](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/6)
  (F-07 y F-08), fusionado el 03/11/2026 como `a881b53`, y el de la rama
  `security/lab-fsi-enlaces` (F-11, el hueco que encontró la revisión de Codex en
  el #6). Ninguno toca `src/memlab`:
  - `child_path()` (`experiments/_common.py`) arma la ruta dentro de la carpeta
    base y rechaza `..`, rutas absolutas, subcarpetas y enlaces simbólicos que
    apunten fuera. Resuelve la ruta con `os.path.realpath` y comprueba su prefijo,
    que es el patrón que CodeQL recomienda para `py/path-injection`.
  - `compute()` (`experiments/compute_metrics.py`) la usa al leer
    `evidence/runs/<corrida>` y al escribir `evidence/metrics/<corrida>.json`.
  - `new_run_dir()` valida el perfil con `Profile` antes de crear la carpeta, así
    que un perfil mal escrito ya no deja carpetas ni vacía `data/`.
- Prueba de regresión: `tests/test_rutas_experimentos.py`, 15 casos con carpetas
  temporales y sin modelo. Sobre `main` sin ninguna corrección, 11 de los 13
  primeros fallaban; los 2 de enlaces simbólicos fallaban todavía con la
  corrección de F-07 y F-08. Con las dos correcciones pasan los 15, y `make test`
  da 45 de 45. Las salidas están en
  [`docs/lab5/evidencia/remediacion/`](lab5/evidencia/remediacion/).
- Corridas válidas: `make metrics` recalculó las métricas de todas las corridas de
  `evidence/runs/`, y quedaron idénticas a las versionadas.
- Desde la línea de comandos: `compute_metrics.py ../fuera` y
  `run_t02.py --profile secur` terminan con código 1 sin leer, escribir ni crear
  nada; `evidence/runs/` sigue con las mismas 12 carpetas.
- Evidencia de reescaneo:
  - CodeQL 2.27.4, la misma versión antes y después: el análisis de Python de
    `main` pasó de 9 resultados (`939f78d`) a 0 (`a881b53`). Las alertas #1 a #5,
    #8 y #9 quedaron *Fixed* el 03/11/2026 a las 23:54 UTC; #6 y #7 siguen
    descartadas y ya no se detectan.
  - Semgrep 1.183.0 en Actions: 22 hallazgos antes y 22 después, con la misma
    distribución y ninguno en `experiments/` ni en `tests/`. Semgrep no detectaba
    F-07 ni F-08, y la corrección no agrega hallazgos. Los JSON de las dos
    corridas están en `remediacion/`.
  - SCA y DAST no se repitieron: la corrección no cambia dependencias ni la
    superficie HTTP.
- Riesgo residual y decisión: bajo. Quien corre los experimentos sigue
  controlando sus argumentos, pero ya no puede leer ni escribir fuera de
  `evidence/`, tampoco a través de un enlace simbólico, ni dejar carpetas
  sobrantes por un error de tipeo.

## 5. Pentest autorizado
Validación manual del punto 6, hecha el 03/11/2026. Corresponde al hallazgo F-10.

- **Hipótesis:** la API de Ollama que usa `memlab` no exige autenticación. Su
  control de acceso depende solo de dos cosas: que escuche en loopback y que
  rechace las peticiones de navegador que vienen de otros sitios (CORS).
- **Entorno de pruebas aislado:** el Mac del equipo, con Ollama 0.34.2 arrancado
  con `ollama serve` y sin variables `OLLAMA_*`. El modelo es el del laboratorio,
  con el mismo digest de las corridas oficiales (`46e0c10c…`). Sin datos personales.
- **Solicitudes inocuas y respuestas observadas:** solo `GET /api/version` y
  `GET /api/tags`. El script y su salida están en
  [`docs/lab5/evidencia/validacion-manual/`](lab5/evidencia/validacion-manual/),
  sin la IP de red ni el usuario local.

| Prueba | Petición | Respuesta | Qué muestra |
|---|---|---|---|
| P1 | `GET /api/version` sin credenciales | `200` | No hay autenticación |
| P2 | `GET /api/tags` sin credenciales | `200`, con la lista de modelos | Cualquiera que llegue al puerto ve qué modelos hay |
| P3 | `GET /api/version` por la IP de red del equipo | Conexión rechazada | No es accesible desde la red |
| P4 | `GET /api/version` con `Origin: http://evil.local` | `403` | Un sitio web abierto en el navegador no puede usarla |
| P5 | `GET /api/version` con `Origin: http://localhost:3000` (control) | `200`, con `Access-Control-Allow-Origin` | El rechazo de P4 se debe al origen |

- **Resultado: validado.** La API no exige autenticación (P1 y P2), y las dos
  mitigaciones funcionan (P3, P4 y P5). Cualquier proceso del equipo puede usarla,
  incluso desde un contenedor: en el punto 5, ZAP la alcanzó a través de
  `host.docker.internal`.
- **Impacto:** para aprovecharlo hay que poder ejecutar código en el equipo. Con
  eso, un proceso podría usar el modelo o reemplazarlo por otro con el mismo
  nombre, y alterar las corridas (integridad). Las rutas que modifican modelos
  (`/api/pull`, `/api/create`, `/api/copy` y `/api/delete`) no se probaron, porque
  cambiarían el estado del laboratorio. Un reemplazo se notaría: el
  `manifest.json` de cada corrida guarda el digest que `fingerprint()` lee de
  `/api/tags` (`src/memlab/llm.py:57`), y P2 muestra el digest oficial.
- **Recomendación:** mantener Ollama solo en loopback. Eso significa no usar
  `OLLAMA_HOST=0.0.0.0`, no publicar el puerto 11434 en `docker-compose.yml` (hoy
  no lo publica) y no ampliar `OLLAMA_ORIGINS`. Si algún día se expusiera, debería
  ir detrás de un proxy con autenticación y TLS. Del lado de `memlab`,
  `MEMLAB_OLLAMA_HOST` acepta cualquier URL (`src/memlab/config.py:67`) y el
  cliente habla HTTP sin credenciales (`src/memlab/llm.py:34`): apuntarlo a un
  Ollama remoto enviaría el contexto, con las memorias, sin cifrar.
- **Prueba de regresión:** volver a correr `validar-ollama.sh` después de cualquier
  cambio de configuración de Ollama. El script compara cada respuesta con la
  esperada (P1, P2 y P5 en `200`, P3 sin conexión y P4 en `403`) y termina con
  código 1 si alguna no coincide, si Ollama no responde o si P3 no se puede
  comprobar. Con Ollama apagado da 4 fallas y código 1; con Ollama activo, las 5
  pruebas pasan y termina con código 0.
