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
| Semgrep (`p/owasp-top-ten` + `p/secrets`) | SAST | 21/10/2026 | Corrida local: 220 reglas, 107 archivos, 12 hallazgos (1 ERROR, 11 WARNING). En Actions: pendiente de la primera ejecución. | Artefacto `resultado-semgrep` del workflow `seguridad-estatica.yml` |
| CodeQL Default setup | SAST | — | Pendiente de habilitar en Settings | Pestaña Security → Code scanning |
| Gitleaks | Secretos | — | Pendiente de la primera ejecución en Actions | Job `Gitleaks (secret scanning)` |
| GitHub secret scanning + push protection | Secretos | 21/10/2026 | Habilitado (consultado por API) | Settings → Advanced Security |
| Dependabot alerts | SCA | 21/10/2026 | Habilitado; 0 alertas abiertas | Pestaña Security → Dependabot |
| pip-audit 2.10.1 | SCA | 21/10/2026 | Versiones mínimas: 5 vulnerabilidades en 2 paquetes. Últimas versiones: 5 en 1 paquete | [`docs/lab5/evidencia/`](lab5/evidencia/) y artefacto `resultado-pip-audit` |
| OWASP ZAP Baseline | DAST pasivo | — | Pendiente (punto 5) | — |

**Por qué Dependabot muestra 0 alertas.** El proyecto declara rangos (`chromadb>=0.5.0`)
en `pyproject.toml` y no versiona un archivo de bloqueo, así que Dependabot no sabe
qué versión exacta se instala. Para compensarlo, el workflow resuelve las
dependencias con `uv pip compile` y las audita con `pip-audit` (job `sca`). Se
auditaron los dos extremos del rango: las versiones **mínimas** que permite
`pyproject.toml` y las **últimas** que instala hoy `make setup`.

## 3. Hallazgos y gestión
| ID | Categoría | Descripción sin secretos | Riesgo | Archivo/ruta | Cambio propuesto | Estado |
|---|---|---|---|---|---|---|
| F-01 | SAST · CWE-250 | El contenedor corre como `root`: el `Dockerfile` no define `USER` (Semgrep `dockerfile.security.missing-user`). | Medio | `Dockerfile:16` | Crear un usuario sin privilegios y añadir `USER` antes de `CMD`. | Abierto |
| F-02 | SAST · CWE-829 | Las acciones de GitHub se referencian por etiqueta mutable (`@v4`, `@v5`, `@v3`), no por SHA (Semgrep `github-actions-mutable-action-tag`). | Bajo | `.github/workflows/seguridad-estatica.yml` | Fijar cada acción a su SHA; Dependabot (`github-actions`) las mantiene al día. | Abierto |
| F-03 | SCA · CVE-2026-45829/45830/45831/45833 | `chromadb` (todas las versiones del rango) tiene ejecución de código y falta de aislamiento entre tenants **en su servidor HTTP**. Sin versión corregida. | No aplica | `pyproject.toml` | Ninguno inmediato: ver análisis abajo. Vigilar el aviso. | Aceptado |
| F-04 | SCA · CVE-2025-71176 | `pytest` ≤ 9.0.2 usa `/tmp/pytest-of-{usuario}` de forma insegura en UNIX. El rango `pytest>=8.0` lo permite. | Bajo | `pyproject.toml` (extra `dev`) | Subir el piso a `pytest>=9.0.3`. | Abierto |
| F-05 | Revisión manual · CWE-798 | Clave HMAC de desarrollo fija en el código; se usa en silencio si no se exporta `MEMLAB_HMAC_KEY`. Semgrep `p/secrets` no la detectó. | Medio | `src/memlab/config.py:37` | Exigir la variable en corridas oficiales (fallar si falta) o dejar constancia en el manifiesto. | Abierto |

Las 11 advertencias de Semgrep son 5 en el workflow del proyecto y 6 en las copias
del kit del profesor (`Kit_Integracion_AppSec_GitHub_FSI/`); las del kit son
duplicados y se cuentan como un solo hallazgo (F-02).

### Análisis SCA (punto 4)

**Dependencia seleccionada: `chromadb`.**
- Versión: el rango es `>=0.5.0`; hoy se resuelve `1.5.9`. Ninguno de los cuatro
  avisos tiene versión corregida.
- ¿Aplica al código? **No es explotable en este proyecto.** Los cuatro avisos
  afectan al servidor HTTP de ChromaDB (rutas `/api/v2/tenants/...` y
  `SimpleRBACAuthorizationProvider`). El laboratorio usa el cliente embebido
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
- Observación: CVE-2026-45830/45831 (falta de aislamiento entre tenants) es el
  mismo tipo de falla que el control C1 corrige en la capa de recuperación. Aquí no
  depende del RBAC de ChromaDB: en el perfil `secure`, el filtro por
  `tenant_id`/`user_id` lo aplica el propio `retriever.py` en cada consulta.

**Dependencia secundaria: `pytest`.**
- Versión: el piso `>=8.0` permite versiones vulnerables (8.0.0 en la resolución
  mínima); `make setup` instala hoy `9.1.1`, que no es vulnerable.
- ¿Aplica? Solo en desarrollo y en equipos UNIX compartidos. Los tests usan
  `tmp_path` (`tests/conftest.py:19`). En macOS el directorio temporal es por
  usuario (`$TMPDIR`) y el runner de Actions es efímero y de un solo usuario, así
  que el riesgo práctico es bajo.
- Medida correctiva: subir el piso a `pytest>=9.0.3`. Es compatible, porque la
  resolución actual ya usa la 9.1.1. Es candidato a la remediación del punto 7.

## 4. Validación antes y después
- Evidencia inicial (captura o artefacto): Semgrep local y pip-audit del 21/10/2026 (ver sección 2).
- Pull request con corrección: pendiente (punto 7).
- Evidencia de reescaneo: pendiente.
- Riesgo residual y decisión: pendiente.

## 5. Pentest autorizado
- Hipótesis: pendiente (punto 6).
- Entorno de pruebas aislado:
- Solicitudes inocuas y respuestas observadas (sin datos personales):
- Resultado: validado / no reproducible / requiere revisión
- Recomendación y prueba de regresión:
