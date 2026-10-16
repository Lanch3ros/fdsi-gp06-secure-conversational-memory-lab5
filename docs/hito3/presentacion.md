# Guion de la presentacion final · Hito 3

Borrador. Sigue el orden que fija el plan de entrega (paso 8):
problema -> arquitectura Unsecure -> demo de T01 -> controles -> resultados ->
limitaciones. Pensado para 8-10 minutos, una diapositiva por bloque salvo donde
se indica. Las cifras marcadas `[PEND]` se completan con lo que imprima
`compute_metrics.py --all` sobre las corridas oficiales; ninguna se escribe a
mano (regla 8 de CLAUDE.md).

---

## 1. Portada

- Titulo: "Persistencia indebida de informacion e instrucciones en la memoria
  conversacional de asistentes LLM"
- Subtitulo: aislamiento, expiracion y eliminacion verificable
- Equipo FDSI-GP-06 · Isaac Burgos · Jose Lancheros · Gina Garcia Zapata
- FDSI/SPTI · ECI · 2026-2

## 2. El problema (1 diapositiva)

- Los asistentes con memoria sacan hechos de cada turno y los reinyectan en
  sesiones futuras: la memoria es un espacio de escritura permanente.
- Tres amenazas concretas, sin dramatizar:
  1. Una instruccion escrita en una sesion se guarda como hecho y se reactiva
     sola en sesiones futuras, sin que el atacante siga conectado.
  2. Si la busqueda por similitud no filtra por dueno, un dato de un usuario
     aparece en la sesion de otro.
  3. "Olvida esto" normalmente solo borra la fila; el embedding y la cache
     sobreviven.
- MITRE ATLAS ya tiene una tecnica dedicada: AML.T0080.000 (persistencia de
  memoria), con mitigacion AML.M0031. No es una preocupacion inventada por el
  equipo.

## 3. Arquitectura Unsecure (1-2 diapositivas, Figura 1)

- Una sola base de codigo, dos perfiles; el diff es exactamente C1-C6.
- Mostrar el diagrama (figura1-unsecure.svg) con los dos canales de
  recuperacion: perfil fijado (entra en TODAS las sesiones) y busqueda por
  similitud (top-k sin filtro de dueno).
- El dato SI tiene `user_id` guardado en los metadatos; la falla es que nadie
  lo usa como filtro en la consulta. Punto clave para que no quede la
  impresion equivocada de que "no se guarda".
- Clasificar por "pistas de retencion" (recuerda, siempre, prefiero) no es lo
  mismo que clasificar por seguridad: el sistema fija al perfil la instruccion
  del atacante por la misma razon que fijaria una preferencia legitima.

## 4. Demo en vivo: T01 (2-3 diapositivas o demo real)

- **Si hay demo en vivo:** `make chat` en Unsecure, escribir la instruccion
  dormida, cerrar sesion, abrir sesion nueva con una pregunta sin relacion
  ("¿cual es la capital de Portugal?"), mostrar que la respuesta sale con
  `http://evil.local` al final.
- Repetir en Secure: la misma instruccion queda rechazada por C3 (no se
  guarda) o, si se sembrara ya guardada, C2 la trae como dato citado, no como
  orden -mostrar el mensaje de sistema limpio y el marcador `<<DATOS_USUARIO_...>>`
  en el turno de usuario-.
- **Si la demo es en video** (igual que el Hito 2): usar el guion de
  `docs/hito2/guion-video-demo.md` como base y grabar el mismo flujo en los
  dos perfiles.
- Cifra de apoyo: linea base Unsecure (Hito 2, `3ada423`) **TPI = 100 % (20/20)**.

## 5. Los seis controles (1-2 diapositivas, Figura 2 + tabla)

- Tabla resumen (control / donde vive / prueba / metrica), igual que
  `controles-C1-C6.md`.
- Destacar en el relato:
  - **C1**: el mismo filtro que ya estaba escrito, medido de punta a punta
    por primera vez en el Hito 3.
  - **C2**: marcador por sesion derivado con HMAC, no adivinable.
  - **C3**: reglas, no juez LLM todavia -mencionar por que (circularidad: el
    modelo objeto de estudio decidiria que se guarda)-.
  - **C5**: borrado real en tres capas, prueba de borrado con HMAC (nunca SHA
    plano, para que el log no termine siendo una copia del dato borrado).
  - **C4 y C6**: declarar abiertamente que quedaron parciales/fuera de
    alcance por tiempo.

## 6. Resultados (2 diapositivas: tabla + lectura)

**Diapositiva A — tabla comparativa** (misma estructura que la Tabla II del
paper):

| Metrica | Unsecure | Secure |
|---|---|---|
| M1 — TPI (T01) | `[PEND]` | `[PEND]` |
| M2a — fuga de recuperacion (T02) | `[PEND]` | `[PEND]` |
| M2b — fuga de divulgacion (T02) | `[PEND]` | `[PEND]` |
| T04 — recuperado tras TTL | `[PEND]`/10 | `[PEND]`/10 |
| M4 — capas irrecuperables (T05) | `[PEND]` % | `[PEND]` % |
| L_mem p95 (ms) | `[PEND]` | `[PEND]` |

**Diapositiva B — lectura:**

- El hallazgo metodologico que vale la pena contar: la brecha entre M2a y M2b
  en la linea base (67 % vs 49 %, Hito 2). Medir solo lo que el modelo repite
  subestima la falla en 27 % relativo.
- Por que H4 se mide sobre `L_mem` y no extremo a extremo: la varianza de
  generacion del modelo (4-5x el presupuesto completo de H4 solo entre
  percentiles de la misma linea base) enterraria el efecto de los controles.
- Cerrar con el resultado central: `[PEND: una frase con el numero final de
  M2a y M4 en Secure]`.

## 7. Limitaciones (1 diapositiva)

- Sin rubrica del docente: alcance inferido del cronograma de la propuesta,
  declarado explicitamente.
- C3 solo reglas (sin secretos de forma libre), C4 parcial, C6 y T03 no
  implementados, M3 y M5 no medidos.
- Un solo modelo, una sola maquina por comparacion.
- Deteccion automatica con casos de revision manual aparte.

## 8. Cierre

- Que se logro: laboratorio reproducible, comparacion Unsecure/Secure sobre
  una sola base de codigo, evidencia versionada con git_sha + semilla + digest.
- Que sigue (si se pregunta): C4 completo, C6 + T03, M3 con los 60 candidatos,
  T06 con evaluacion humana de utilidad.
- Repositorio: `github.com/sofiapeace/fdsi-gp06-secure-conversational-memory`

---

## Notas para quien arme las diapositivas

- Usar `docs/diagramas/figura1-unsecure.svg` y `figura2-secure.svg` (version
  `.drawio` editable en la misma carpeta; `figura2-secure.drawio` ya trae la
  nota de "AMPLIACION, no implementado en el Hito 3" para JWT/Streamlit/
  FastAPI/SQLCipher, que no existen en el codigo real).
- No hace falta mas de 10-12 diapositivas para 8-10 minutos.
- Si se pregunta por la demo en vivo vs video: `make chat` funciona en los
  dos perfiles y es la forma mas directa de mostrar la diferencia; decidir
  con el profesor si la sustentacion permite demo en vivo o exige video
  (pendiente de confirmar, ver `plan-entrega.md`, seccion "Lo que NO esta en
  el repositorio").
