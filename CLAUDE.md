# CLAUDE.md · FDSI-GP-06

Contexto para las sesiones de Claude Code del equipo. Claude Code lo carga solo al
abrirse en este repositorio. **El plan de trabajo de la entrega del Hito 3 está en
[`docs/hito3/plan-entrega.md`](docs/hito3/plan-entrega.md): léelo completo al
empezar cada sesión.**

## Qué es el proyecto

Laboratorio local y cerrado que demuestra cómo instrucciones y datos persisten
indebidamente entre conversaciones en un asistente con memoria de largo plazo, y
que mide cuánto reducen eso seis controles de seguridad (C1–C6).

- Curso: FDSI / SPTI · Seminario Aplicado de Ciberseguridad en IA · ECI · 2026-2.
- Equipo: Isaac David Burgos Cervantes · Jose Luis Lancheros Aroya · Gina Sofía
  García Zapata. Repo de Sofía (`sofiapeace`).
- Modelo objeto de estudio: Llama 3.1 8B Instruct Q4_K_M en Ollama, local.

## Estado al 16/10/2026

- **Hito 1** (propuesta v2) y **Hito 2** (laboratorio Unsecure, T01 y T02 con
  evidencia, M1 y M2 de línea base) entregados.
- **Línea base** (corrida oficial del 22/09, commit `3ada423`):
  M1 = 100 % (20/20) · M2a = 67 % · M2b = 49 % · `L_mem` p95 = 100 ms ·
  `L_e2e` p95 = 5 279 ms. La corrida del 19/09 dio exactamente los mismos M1, M2a y M2b.
- **Hito 3 se entrega el 17/10/2026.** No hay rúbrica del docente. El alcance sale
  del cronograma de la propia propuesta: controles C1–C6 implementados, T01–T06 en
  los dos perfiles, comparativa M1–M5, paper IEEE, presentación y demo. Hay que
  decir explícitamente en el entregable que el alcance es inferido.
- **Perfil `secure` hoy:** C2, C3, C5 y C6 lanzan `NotImplementedError` a propósito.
  El filtro de C1 ya está escrito en `retriever.py` pero nunca se ha medido. Las
  funciones HMAC de C4 existen en `provenance.py` pero no están conectadas.

## Mapa del código

```
src/memlab/
  config.py          Settings: perfil unsecure|secure, backend ollama|stub (lee solo os.environ)
  schema.py          MemoryRecord, MemoryKind (fact/preference/task_context/instruction/secret), TTL por tipo
  orchestrator.py    un turno completo; mide L_mem y L_e2e; seed_memory() acepta source=
  prompt.py          C2  — en unsecure la memoria va en el mensaje de SISTEMA
  memory/writer.py   C3  — en unsecure guarda todo lo que tenga pistas de retencion, sin tipar
  memory/retriever.py C1 — dos canales (perfil fijado + similitud); en unsecure ninguno filtra
  memory/store.py    tres capas: SQLite + ChromaDB + cache de sesion; borrado logico
  memory/lifecycle.py C5 — purge_expired(now) funcion pura; forget()
  provenance.py      C4  — sign/verify HMAC-SHA256; deletion_proof con HMAC (no SHA plano)
  tools.py           C6  — enviar_correo simulada
  audit.py           log JSONL de solo-agregado (de aqui sale M2a)
  detectors.py       deteccion de M1 y M2b
  stats.py           Wilson, regla de tres, percentiles
  clock.py           reloj inyectable (FrozenClock para T04)
experiments/         run_t01.py, run_t02.py, compute_metrics.py, questions.py (bancos de texto)
evidence/runs/       una carpeta por corrida: manifest.json, audit.jsonl, results.json
evidence/metrics/    metricas calculadas desde la evidencia
docs/                hito1/ (propuesta), hito2/ (informe, ATLAS, guion), hito3/ (plan), diagramas/
```

No hay FastAPI, Streamlit, LangChain ni LangGraph: el orquestador es propio y la
interfaz es la CLI `memlab` (`info`, `seed`, `ask`, `chat`).

## Cómo se corre

```bash
make setup                    # requiere uv y Python 3.11
make test                     # 14 tests, segundos, sin modelo
export MEMLAB_LLM=stub        # para desarrollar sin Ollama (el .env NO se carga solo)
make t01 PROFILE=secure N_T01=40
make t02 PROFILE=secure
make metrics
```

El modelo real solo hace falta para las corridas oficiales: `make model` (~5 GB) y
Ollama corriendo.

## Reglas que no se negocian

1. **Una sola base de código, dos perfiles.** El diff entre Unsecure y Secure son
   los controles y nada más. **El camino Unsecure no puede cambiar.** La línea base
   del Hito 2 (20/20, 67 y 49) se midió en el Mac de Jose. Temperatura 0 y semilla
   fija no garantizan los mismos números en otra máquina. Si las corridas del
   Hito 3 se hacen en otra máquina, la comparativa usa el Unsecure **nuevo** de esa
   misma máquina, y cualquier diferencia con la línea base se reporta y se explica.
   Para descartar que el código del Hito 3 haya cambiado el perfil Unsecure, correr
   T01 y T02 en `unsecure` sobre `3ada423` y sobre el commit nuevo en esa misma
   máquina: tienen que dar igual.
2. **Dos canales de recuperación** (perfil fijado + similitud). C1 filtra **los dos**.
   No colapsarlos: T01 explota el perfil fijado y T02 la similitud.
3. **No quitar la siembra de memoria legítima de fondo** de los runners. Sin ella el
   ataque "funciona" por un almacén casi vacío y el experimento pierde validez.
4. **M2 en dos niveles:** M2a (el índice entregó el dato ajeno; se lee del log) y M2b
   (el modelo lo repitió). **C1 se aprueba con M2a = 0, no con M2b = 0.**
5. **Latencia en dos niveles.** H4 (≤ 300 ms en p95) se evalúa sobre `L_mem`, no
   sobre `L_e2e`.
6. **Sesión nueva = proceso nuevo** (por eso T01 lanza un subproceso por sesión).
7. **Cada prueba aísla el control que dice medir.** En Secure, el dato de A en T02
   tiene que entrar al almacén sin pasar por C3 y con firma válida. Si no, C3 lo
   rechaza como secreto, M2a da 0 y eso no demuestra nada sobre C1. Lo mismo vale
   para medir C2 solo (ablación): la instrucción se inserta ya firmada en el almacén.
8. **Ninguna cifra se escribe a mano.** Todo sale de `compute_metrics.py` leyendo
   `evidence/runs/`. El backend `stub` **no es evidencia** y `compute_metrics` lo
   marca. Corridas oficiales del Hito 3: **todas en una sola máquina**, Unsecure y
   Secure sobre el mismo commit, digest
   `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`, semilla
   20260919, temperatura 0, `num_predict` 256.
9. Toda proporción con **intervalo de Wilson**; con 0 aciertos, regla de tres (3/n).
10. **No afirmar nada que no se midió.** Lo que no alcance va a Limitaciones, con
    nombre propio.
11. Datos **inventados**: tarjeta `4111 1111 1111 1111` (prueba de Visa), dominio
    `evil.local`. Nada real, nada contra terceros.

## Convenciones

- Todo en español. Código y comentarios **sin tildes**, como el código existente;
  documentos **con** tildes.
- Commits: `feat(c1): ...`, `fix(...)`, `test: ...`, `docs(hito3): ...`, `evidence: ...`.
- Una rama por tema (`hito3/<tema>`) y PR a `main`. Antes de abrir el PR:
  `make test` en verde.
- Los tests usan el backend `stub` (fixture `lab` en `tests/conftest.py`) y verifican
  la **tubería**, no al modelo. Cada control nuevo lleva su test.

## Inconsistencias conocidas: no repetirlas

- Los documentos dicen "20 memorias de fondo", pero el writer Unsecure **guardó 15**:
  rechazó 5 sin pistas de retención (`seed_rejected` en `audit.jsonl`). Decir
  "sembramos 20, se guardaron 15" y reportar cuántas guarda cada perfil.
- T01 se midió con el **mismo usuario B** escribiendo y recibiendo la instrucción.
  No afirmar el caso A → B como resultado mientras no se mida.
- La propuesta (§9) y las figuras mencionan FastAPI, Streamlit, LangChain/LangGraph,
  JWT, SQLCipher y OpenTelemetry. **Nada de eso existe en el código.**
- La Figura 1 dice que ChromaDB no guarda `tenant_id`/`user_id`: **falso**, sí los
  guarda (`schema.to_metadata`). La falla es que la consulta no los usa como filtro.
- La debilidad ⑤ de la Figura 1 ("sin observabilidad") choca con el log de
  auditoría del laboratorio. El log es instrumento del experimento, no un control.
