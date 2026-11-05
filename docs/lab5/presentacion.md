# Guion de la sustentación · Lab. No. 05

Guion para la sustentación de hallazgos que pide el profesor: máximo cinco minutos,
en inglés, con los resultados de los cuatro análisis (SAST, SCA, detección de
secretos y DAST). En cada uno hay que responder cuatro preguntas: qué encontramos y
con qué criticidad, cómo lo encontramos, cómo lo solucionamos y cómo lo validamos.

Las diapositivas, con sus notas de orador en inglés, están en la presentación
[Lab 05 Security Findings](https://claude.ai/artifact/WLGF6m2HkUPVibvDW18HiH); solo
la abre quien la tenga compartida. El detalle de cada hallazgo está en
[`../REPORTE_HALLAZGOS.md`](../REPORTE_HALLAZGOS.md) y [`../SECURITY.md`](../SECURITY.md).

## Orden y tiempos

| # | Diapositiva | Qué responde | Tiempo | Presenta |
|---|---|---|---|---|
| 1 | Portada | Quiénes somos y qué vamos a mostrar | 10 s | |
| 2 | Resumen | El hallazgo principal de cada análisis, con su criticidad y su estado | 25 s | |
| 3 | SAST, qué encontramos y cómo | Qué y cómo | 50 s | |
| 4 | SAST, corrección y validación | Cómo lo solucionamos y cómo lo validamos | 65 s | |
| 5 | SCA | Las cuatro preguntas | 40 s | |
| 6 | Detección de secretos | Las cuatro preguntas | 35 s | |
| 7 | DAST | Las cuatro preguntas | 50 s | |
| 8 | Lo que nos llevamos | Qué vieron y qué no vieron las herramientas | 25 s | |

En total son unos cinco minutos. SAST tiene dos diapositivas porque es el único
análisis con el ciclo completo de corrección y reescaneo.

## Las cuatro preguntas, por análisis

### SAST
- **Qué:** 9 alertas `py/path-injection` de CodeQL (CWE-22, alta): 7 reales (F-07 y
  F-08) y 2 falsos positivos. Semgrep dio 17 hallazgos: 11 reales (F-01 media, F-02 y
  F-06 bajas) y 6 falsas alarmas en la carpeta del kit.
- **Cómo:** Semgrep corre en cada PR con GitHub Actions, y CodeQL en Default setup.
  Con la configuración por defecto CodeQL dio 0; con la suite `extended` y amenazas
  `remote_and_local` aparecieron las 9.
- **Solución:** `child_path()` y la validación del perfil en `new_run_dir()` (PR #6,
  #7 y #8). La revisión de Codex encontró dos formas de saltar la corrección con
  enlaces simbólicos (F-11), y también se corrigieron.
- **Validación:** CodeQL pasó de 9 resultados a 0 con la misma versión. La prueba de
  regresión pasó de 11 fallas en 13 casos a 17 de 17, y `make metrics` dio las mismas
  métricas.
- **Evidencia para mostrar:** la [captura 06](evidencia/capturas/06-code-scanning-extended.webp),
  [`pytest-antes.txt`](evidencia/remediacion/pytest-antes.txt),
  [`pytest-despues.txt`](evidencia/remediacion/pytest-despues.txt) y las alertas
  cerradas en [code scanning](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/security/code-scanning?query=is%3Aclosed).

### SCA
- **Qué:** 4 CVE de `chromadb` sin versión corregida (2 críticos y 2 altos) y 1 de
  `pytest` (medio).
- **Cómo:** `pip-audit` en Actions sobre las versiones mínimas y las últimas que
  permite `pyproject.toml`, más las alertas de Dependabot. Las dos herramientas
  coinciden aviso por aviso.
- **Solución:** los de `chromadb` no aplican, porque son de su servidor HTTP y usamos
  el cliente embebido, así que se descartaron como *not used*. Para `pytest`, la
  propuesta es subir el piso a 9.0.3. El PR #2 de Dependabot se cerró sin fusionar.
- **Validación:** las alertas quedaron cerradas en Dependabot con su justificación.
- **Evidencia para mostrar:** las capturas [09](evidencia/capturas/09-dependabot-alertas.webp),
  [10](evidencia/capturas/10-dependabot-chromadb-descartadas.webp) y
  [11](evidencia/capturas/11-pr2-cerrado.webp).

### Detección de secretos
- **Qué:** ningún secreto expuesto. En la revisión manual apareció F-05, una clave
  HMAC de desarrollo fija en `src/memlab/config.py:37` (CWE-798, media).
- **Cómo:** Gitleaks en cada PR sobre todo el historial, y la detección de secretos
  de GitHub con push protection.
- **Solución propuesta:** exigir `MEMLAB_HMAC_KEY` en las corridas oficiales y fallar
  si falta.
- **Validación:** pendiente, porque F-05 sigue abierto. Hay que decirlo así.
- **Evidencia para mostrar:** el [run de Actions del PR #1](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/actions/runs/39690739269),
  con Gitleaks en verde, y la [captura 03](evidencia/capturas/03-settings-ai-secret-protection.webp).

### DAST
- **Qué:** ZAP Baseline dio 0 fallas y 3 advertencias por encabezados (F-09, baja). La
  validación manual confirmó que la API de Ollama no exige autenticación (F-10,
  CWE-306, baja).
- **Cómo:** no hay staging web, así que ZAP corrió en Docker contra la API de Ollama
  en `localhost:11434`, la alternativa que permite el enunciado. F-10 se probó con
  cinco peticiones de solo lectura.
- **Solución:** se aceptan, porque la API solo escucha en `127.0.0.1` y rechaza con
  403 los orígenes ajenos.
- **Validación:** `validar-ollama.sh` termina con código 0 si todo sigue igual y con
  código 1 si algo cambia.
- **Evidencia para mostrar:** el [informe de ZAP](evidencia/zap-local/zap-report.html)
  y la [salida de la validación](evidencia/validacion-manual/ollama-sin-autenticacion.txt).

## Demostración en vivo, si sobra tiempo
Desde la raíz del repositorio, con `make setup` ya hecho:

```bash
.venv/bin/python -m pytest -q tests/test_rutas_experimentos.py
```

Resultado esperado: `17 passed`.

```bash
.venv/bin/python experiments/compute_metrics.py ../fuera
```

Resultado esperado: `nombre no valido, sale de …/evidence/runs: '../fuera'`, con
código de salida 1.

## Antes de presentar
- Repartir las diapositivas en la columna «Presenta».
- Compartir la presentación con el equipo y ensayarla una vez con cronómetro.
- Correr una vez los dos comandos de la demostración.
- Dejar abiertas las alertas cerradas de code scanning, los PR #6 y #7 y `SECURITY.md`.

## Preguntas probables
Las respuestas están en inglés, como la exposición.

- **Why is there no DAST against an HTTPS staging site?** memlab is a command line
  tool with no web service. The lab allows a local baseline with Docker, so we
  scanned the only HTTP surface in the system, the Ollama API.
- **Why did you not upgrade chromadb?** Its four CVEs have no fixed version and they
  live in the ChromaDB HTTP server, which we do not use. Changing the version would
  also alter the official experiment runs.
- **How do you know the fix did not change your results?** We did not touch
  src/memlab, and make metrics recomputed every run with identical results.
- **Why is F-05 still open if it is rated medium?** Point 7 asked for one small fix
  we could trace and rescan, and CodeQL could confirm the fix for F-07 and F-08. F-05
  is the next one.
- **What did the code review teach you?** A fix the tools confirm can still have
  gaps. Codex raised 5 issues in our pull requests and all of them were valid, and
  the rescan had missed the two about symbolic links.
