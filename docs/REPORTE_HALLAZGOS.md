# Informe técnico de hallazgos

**Proyecto:** `memlab`, laboratorio de memoria conversacional segura (FDSI-GP-06). Lab. No. 05: seguridad en el ciclo de desarrollo.  
**Integrantes:** Isaac David Burgos Cervantes · Jose Luis Lancheros Aroya · Gina Sofía García Zapata  
**Repositorio / commit:** https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5 · línea base `6291230` (21/10/2026) · `main` al cierre del punto 7: `44083ac` (03/11/2026)  
**Entorno autorizado:** el repositorio y el Mac del equipo. No hay staging: `memlab` es una herramienta de línea de comandos sin servicio web, así que el DAST se hizo en local contra la API de Ollama del laboratorio (`127.0.0.1:11434`). Solo datos ficticios.  
**Fecha:** 21/10/2026 a 03/11/2026  

El registro completo, con los 11 hallazgos (F-01 a F-11), las herramientas y las capturas, está en [`SECURITY.md`](SECURITY.md).

## Resumen ejecutivo
1. **Rutas armadas con argumentos de la línea de comandos (F-07, F-08 y F-11). Corregido.**
   `compute_metrics.py` y tres runners de `experiments/` usaban el nombre de la
   corrida y el perfil para leer, escribir, crear carpetas y vaciar `data/` sin
   validarlos. CodeQL lo marcó con 7 alertas `py/path-injection`. Se corrigió con
   una prueba de regresión, y CodeQL pasó de 9 resultados a 0. La revisión
   automática de código encontró dos veces que la corrección no cubría los enlaces
   simbólicos (F-11), y las dos se corrigieron.
2. **Clave HMAC de desarrollo fija en el código (F-05). Abierto, riesgo medio.**
   Las firmas de procedencia (C4) y las pruebas de borrado (C5) usan esa clave en
   silencio si no se exporta `MEMLAB_HMAC_KEY`, y la clave está en el repositorio
   público. Ninguna herramienta lo detectó: salió de la revisión manual.
3. **API del modelo sin autenticación (F-10). Validado y aceptado.** La API de
   Ollama que usa `memlab` responde sin credenciales. Se validó a mano que sus dos
   mitigaciones funcionan: escucha solo en `127.0.0.1` y rechaza con 403 las
   peticiones de navegador que vienen de otros sitios.

Ninguna herramienta detectó la falla más importante del proyecto: en el perfil
`unsecure`, `src/memlab/memory/retriever.py` recupera memorias de otros usuarios.
Es una falla de lógica de autorización, y la mide el experimento T02 del propio
laboratorio.

## Metodología
Identificación del alcance → SAST → detección de secretos → SCA → DAST pasivo → validación manual no destructiva → corrección → reescaneo.

| Etapa | Herramienta | Dónde | Resultado |
|---|---|---|---|
| Alcance | — | `SECURITY.md`, sección 1 | Línea base `6291230`, activos y riesgo principal |
| SAST | Semgrep 1.182.0 y 1.183.0 (`p/owasp-top-ten`, `p/secrets`) | GitHub Actions | 17 hallazgos en el PR #1; 22 desde el punto 5, por 5 falsas alarmas en el informe de ZAP |
| SAST | CodeQL 2.27.x, Default setup | Code scanning de GitHub | 0 alertas con la configuración por defecto; 9 con la suite `extended` y amenazas `remote_and_local`; 1 de GitHub Actions desde el 03/11 |
| Secretos | Gitleaks v3; Secret Protection con push protection | Actions y GitHub | Sin secretos en todo el historial |
| SCA | pip-audit 2.10.1 y Dependabot | Actions, local y GitHub | 4 CVE de `chromadb` que no aplican y 1 de `pytest` |
| DAST pasivo | OWASP ZAP 2.17.0 Baseline | Docker en local, contra Ollama | 0 FAIL y 3 WARN por encabezados HTTP |
| Validación manual | `curl` con `validar-ollama.sh` | Mac del equipo | Hipótesis de F-10 validada |
| Corrección y reescaneo | pytest, CodeQL y Semgrep | PR #6, #7 y el de este informe | Las 7 alertas de F-07 y F-08 quedaron *Fixed*; prueba de regresión de 17 casos |

## Hallazgo F-07 y F-08 · Rutas armadas con argumentos de la línea de comandos
- **Título:** el nombre de la corrida (`compute_metrics.py`) y el perfil
  (`run_t02.py`, `run_t04.py` y `run_t05.py`) se usaban en rutas sin validarlos.
- **Categoría OWASP/CWE:** A01:2021 Broken Access Control · CWE-22. Regla de CodeQL
  `py/path-injection`.
- **Severidad y justificación:** CodeQL la califica alta; el riesgo real es bajo.
  Para explotarla hay que controlar los argumentos o el `MEMLAB_PROFILE` de quien
  corre el experimento, y esa persona ya tiene esos permisos. El caso más probable
  era un error de tipeo: `make t02 PROFILE=secur` dejaba una carpeta en
  `evidence/runs/` antes de fallar.
- **Evidencia minimizada, sin credenciales ni datos personales:**
  - Las 7 alertas abiertas de CodeQL, #1 a #5, #8 y #9
    ([captura 06](lab5/evidencia/capturas/06-code-scanning-extended.webp)).
  - La prueba de regresión sobre el código sin corregir: fallan 11 de 13 casos
    ([`pytest-antes.txt`](lab5/evidencia/remediacion/pytest-antes.txt)).
    `compute("../fuera")` lee y escribe fuera de `evidence/`, y los runners crean
    la carpeta antes de validar el perfil.
- **Impacto en confidencialidad, integridad o disponibilidad:** integridad de la
  evidencia, de la que salen todas las métricas del proyecto. Se podía leer o
  escribir fuera de `evidence/`, y `reset_lab()` vacía `data/` en la ruta que se
  arma.
- **Pasos de validación segura en entorno propio:** la prueba de regresión usa
  carpetas temporales y no necesita el modelo. Incluso sobre el código vulnerable,
  nada sale del directorio temporal.
- **Corrección (commit / pull request):** commit `b2bf07b`,
  [PR #6](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/6).
  `child_path()` (`experiments/_common.py`) arma la ruta dentro de la carpeta base
  y rechaza `..`, rutas absolutas y subcarpetas; `compute()` la usa al leer y al
  escribir; `new_run_dir()` valida el perfil con `Profile` antes de tocar el disco.
  No se tocó `src/memlab`.
- **Resultado del reescaneo:**
  - CodeQL 2.27.4, la misma versión antes y después: Python pasó de 9 resultados a
    0 en `main`, y las 7 alertas quedaron *Fixed* el 03/11/2026.
  - Semgrep: 22 hallazgos antes y 22 después, ninguno en `experiments/`.
  - La prueba de regresión pasa completa
    ([`pytest-despues.txt`](lab5/evidencia/remediacion/pytest-despues.txt)), y
    `make metrics` da las mismas métricas para todas las corridas versionadas.

## Hallazgo F-11 · La corrección no resolvía enlaces simbólicos
- **Título:** `child_path()` no tenía en cuenta los enlaces simbólicos.
- **Categoría OWASP/CWE:** A01:2021 Broken Access Control · CWE-59.
- **Severidad y justificación:** baja. Hace falta un enlace simbólico dentro de
  `evidence/`. Git guarda enlaces, así que uno podría llegar en un commit, y
  bastaría con correr `make metrics`.
- **Evidencia minimizada:** lo encontró la revisión automática de Codex, en dos
  rondas. Las dos se reprodujeron con pruebas que fallaban antes de su corrección.
  - En el PR #6: un enlace dentro de `evidence/runs/` o `evidence/metrics/` que
    apuntara fuera pasaba la validación, porque se comparaba solo el texto de la
    ruta ([`pytest-enlaces-antes.txt`](lab5/evidencia/remediacion/pytest-enlaces-antes.txt)).
  - En el PR #7: si la propia carpeta base era un enlace, `realpath` tomaba su
    destino como raíz y la comprobación volvía a pasar
    ([`pytest-base-antes.txt`](lab5/evidencia/remediacion/pytest-base-antes.txt)).
- **Impacto en confidencialidad, integridad o disponibilidad:** integridad. A
  través del enlace, `write_json()` habría sobrescrito un archivo fuera de
  `evidence/`.
- **Pasos de validación segura en entorno propio:** los enlaces se crean dentro de
  las carpetas temporales de la prueba.
- **Corrección (commit / pull request):**
  - Commit `1bd3ba0`, [PR #7](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/7):
    `os.path.realpath` en lugar de `os.path.normpath`.
  - Commit `b1a7033`, en el PR de este informe: la ruta resuelta de la carpeta base
    tiene que coincidir con la absoluta.
- **Resultado del reescaneo:** la prueba de regresión pasa los 17 casos
  ([`pytest-base-despues.txt`](lab5/evidencia/remediacion/pytest-base-despues.txt)),
  `make test` da 47 de 47 y CodeQL sigue en 0 resultados de Python.

## Hallazgo F-10 · API del modelo sin autenticación
- **Título:** la API de Ollama (`localhost:11434`) responde sin credenciales.
- **Categoría OWASP/CWE:** A07:2021 Identification and Authentication Failures ·
  CWE-306.
- **Severidad y justificación:** baja. Escucha solo en loopback y rechaza los
  orígenes ajenos, así que para aprovecharla hay que ejecutar código en el equipo.
- **Evidencia minimizada:** la salida del script de validación, sin la IP de red ni
  el usuario local
  ([`ollama-sin-autenticacion.txt`](lab5/evidencia/validacion-manual/ollama-sin-autenticacion.txt)).
- **Impacto en confidencialidad, integridad o disponibilidad:** integridad. Un
  proceso del equipo podría usar el modelo o reemplazarlo por otro con el mismo
  nombre y alterar las corridas. Se notaría, porque cada `manifest.json` guarda el
  digest del modelo.
- **Pasos de validación segura en entorno propio:** solo `GET /api/version` y
  `GET /api/tags`; no se tocaron las rutas que modifican modelos.

  | Prueba | Petición | Respuesta |
  |---|---|---|
  | P1 | `GET /api/version` sin credenciales | `200` |
  | P2 | `GET /api/tags` sin credenciales | `200` |
  | P3 | `GET /api/version` por la IP de red del equipo | Sin conexión |
  | P4 | Con `Origin: http://evil.local` | `403` |
  | P5 | Con `Origin: http://localhost:3000` (control) | `200` |

- **Corrección (commit / pull request):** no aplica: es un componente de terceros y
  las mitigaciones funcionan. Se recomienda mantener Ollama en loopback, no ampliar
  `OLLAMA_ORIGINS` y ponerlo detrás de un proxy con autenticación y TLS si alguna
  vez se expone.
- **Resultado del reescaneo:** `validar-ollama.sh` quedó como prueba de regresión
  ([PR #4](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/4)
  y [PR #5](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/5)).
  Termina con código 0 si las cinco respuestas son las esperadas y con código 1 si
  alguna cambia, si Ollama no responde o si no puede escribir la evidencia. La
  revisión de Codex del PR #5 encontró dos casos en que el script decía "OK" sin
  comprobarlo: un archivo de salida que no se podía escribir y un P5 que solo
  miraba el código `200`. Los dos se corrigieron en el PR de este informe
  ([`casos-de-falla.txt`](lab5/evidencia/validacion-manual/casos-de-falla.txt)).

## Hallazgo F-03 · Dependencia vulnerable que no aplica: `chromadb`
- **Título:** 4 CVE de `chromadb` sin versión corregida.
- **Categoría OWASP/CWE:** A06:2021 Vulnerable and Outdated Components ·
  CVE-2026-45829, CVE-2026-45830, CVE-2026-45831 y CVE-2026-45833.
- **Severidad y justificación:** GitHub califica dos como críticas y dos como
  altas. En este proyecto no aplican: los cuatro avisos son del servidor HTTP de
  ChromaDB, y `memlab` usa el cliente embebido `PersistentClient`
  (`src/memlab/memory/store.py:51`), sin servidor, autenticación ni RBAC.
- **Evidencia minimizada:** pip-audit sobre las resoluciones mínima y última, y las
  alertas de Dependabot
  ([captura 09](lab5/evidencia/capturas/09-dependabot-alertas.webp)).
- **Impacto en confidencialidad, integridad o disponibilidad:** ninguno mientras
  ChromaDB no se despliegue como servicio.
- **Pasos de validación segura en entorno propio:** lectura de los avisos y del
  código; no se levantó ningún servidor.
- **Corrección (commit / pull request):** ninguna. No hay versión corregida, y
  cambiar `chromadb` alteraría las corridas oficiales del proyecto. Las 7 alertas
  se descartaron en Dependabot como *not used*, con su justificación
  ([captura 10](lab5/evidencia/capturas/10-dependabot-chromadb-descartadas.webp)).
- **Resultado del reescaneo:** no aplica.

## Otros hallazgos
| ID | Hallazgo | Riesgo | Estado |
|---|---|---|---|
| F-01 | El contenedor corre como `root` (Semgrep) | Medio | Abierto. Solo se usa en local; el arreglo es agregar `USER` al `Dockerfile` |
| F-02 | Acciones de GitHub con etiqueta mutable (Semgrep: 8; CodeQL: 1) | Bajo | Abierto. El arreglo es fijar cada acción por SHA |
| F-04 | `pytest>=8.0` permite versiones con CVE-2025-71176 | Bajo | Abierto. Subir el piso a `>=9.0.3`. El [PR #2](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/2) de Dependabot se cerró sin fusionar: cambiaba archivos de evidencia y bajaba `pytest` de 9.1.1 a 9.0.3 |
| F-05 | Clave HMAC de desarrollo fija en el código | Medio | Abierto (ver el resumen ejecutivo) |
| F-06 | `dependabot.yml` sin `cooldown` (Semgrep) | Bajo | Abierto, sin efecto mientras las actualizaciones de versión sigan apagadas |
| F-09 | La API de Ollama no envía dos encabezados de seguridad (ZAP) | Bajo | Aceptado: protegen a un navegador, y la API la consume `httpx` |

Se descartaron 13 falsas alarmas: 6 de Semgrep en la carpeta del kit, que nunca se
ejecuta; 5 de Semgrep en el informe HTML de ZAP, que es evidencia y no una página
publicada; y 2 de CodeQL en `src/memlab/audit.py`, donde el perfil ya está validado.

## Reflexión final
- **Lo que identificaron las herramientas.** CodeQL encontró las rutas inseguras,
  pero solo con la suite `extended` y el modelo de amenazas `remote_and_local`. Con
  la configuración por defecto dio 0 alertas, porque `memlab` no recibe entrada
  remota. Semgrep encontró problemas de configuración (el `Dockerfile`, los
  workflows y Dependabot) y nada en el código Python. Dependabot y pip-audit
  coincidieron aviso por aviso, y ZAP solo pudo revisar la portada de Ollama.
- **Lo que omitieron.** Ninguna herramienta detectó la recuperación de memorias de
  otros usuarios en `retriever.py`, que es el riesgo central del proyecto, ni la
  clave HMAC fija (F-05). Para encontrarlas hay que entender qué hace el sistema.
- **Lo que no conviene aceptar a ciegas.** Dependabot alertó sobre los archivos de
  evidencia y no sobre `pyproject.toml`, y su PR #2 hacía más de lo que decía su
  título. Un check en verde tampoco garantiza que no haya hallazgos: los pasos de
  Semgrep y pip-audit nunca fallan, porque terminan en `|| true`.
- **Lo que encontró la revisión de código.** La revisión automática de Codex hizo 5
  observaciones en los PR #4 a #7, y las 5 eran válidas: dos huecos con enlaces
  simbólicos en la corrección de F-07 y F-08, que la prueba de regresión y el
  reescaneo daban por buena, y tres casos en que `validar-ollama.sh` podía decir
  "OK" sin comprobarlo. Las herramientas confirman lo que se les pregunta; una
  segunda mirada pregunta otra cosa.
- **Cómo integrar la seguridad al ciclo de desarrollo.** Mantener el workflow en
  cada PR y quitar el `|| true` de Semgrep cuando termine el triage. Proteger `main`
  con un ruleset que exija los checks, porque hoy un check fallido no bloquea el
  merge. Esperar la revisión automática antes de fusionar: dos veces se fusionó
  antes de que llegara. Y acompañar cada corrección con su prueba de regresión.
