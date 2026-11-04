# Demostración de cinco minutos · Lab. No. 05

Guion para la exposición del punto 8. Sigue los seis bloques que pide el enunciado:
problema, impacto, evidencia, corrección, nueva evidencia y limitaciones. El caso que
se sigue de punta a punta es el de las rutas de `experiments/` (F-07, F-08 y F-11),
porque es el que tiene el ciclo completo. El detalle de todo está en
[`../REPORTE_HALLAZGOS.md`](../REPORTE_HALLAZGOS.md) y [`../SECURITY.md`](../SECURITY.md).

| Bloque | Tiempo | Presenta |
|---|---|---|
| 1. Problema | 0:00 a 0:40 | |
| 2. Impacto | 0:40 a 1:20 | |
| 3. Evidencia | 1:20 a 2:20 | |
| 4. Corrección, con demostración en vivo | 2:20 a 3:20 | |
| 5. Nueva evidencia | 3:20 a 4:15 | |
| 6. Limitaciones | 4:15 a 5:00 | |

## 1. Problema (40 s)
**Qué decir:**
- `memlab` es nuestro laboratorio de memoria de largo plazo para asistentes. Le
  aplicamos el ciclo completo: SAST, secretos, dependencias, DAST, validación
  manual, corrección y reescaneo.
- El hallazgo que vamos a seguir: los scripts de `experiments/` armaban rutas con
  argumentos de la línea de comandos sin validarlos.

**Qué mostrar:** la [captura 06](evidencia/capturas/06-code-scanning-extended.webp),
con las 9 alertas `py/path-injection` de CodeQL.

## 2. Impacto (40 s)
**Qué decir:**
- De `evidence/` salen todas las métricas del proyecto. Con `../` o una ruta
  absoluta se podía leer y escribir fuera de esa carpeta, y un perfil mal escrito
  creaba carpetas y vaciaba `data/` antes de fallar.
- El riesgo real es bajo, porque quien corre el script ya tiene esos permisos, pero
  afecta la integridad de la evidencia.
- Hay otros dos riesgos importantes: la clave HMAC de desarrollo fija en el código
  (F-05, sigue abierta) y la API del modelo sin autenticación (F-10, validada).

**Qué mostrar:** la tabla de hallazgos de la sección 3 de `SECURITY.md`.

## 3. Evidencia (1 min)
**Qué decir:**
- Con su configuración por defecto, CodeQL dio 0 alertas, porque `memlab` no recibe
  entrada remota. Con la suite `extended` y amenazas locales dio 9: 7 reales y 2
  falsos positivos.
- Antes de corregir escribimos la prueba de regresión: sobre el código vulnerable
  fallaban 11 de 13 casos.
- Para el punto 6 validamos a mano la API del modelo, solo con peticiones de
  lectura: responde sin credenciales, pero no es accesible desde la red y rechaza
  con 403 los sitios ajenos.

**Qué mostrar:**
[`pytest-antes.txt`](evidencia/remediacion/pytest-antes.txt) y la tabla P1 a P5 de
la sección 5 de `SECURITY.md`.

## 4. Corrección (1 min, con demostración en vivo)
**Qué decir:**
- `child_path()` arma cada ruta dentro de su carpeta y rechaza `..`, rutas
  absolutas, subcarpetas y enlaces simbólicos. `new_run_dir()` valida el perfil
  antes de tocar el disco. No tocamos el código de `memlab` (`src/memlab`).
- La revisión automática de código encontró dos veces que la corrección no cubría
  los enlaces simbólicos. Las dos tienen su prueba y su corrección (F-11).

**Demostración en vivo:** los dos comandos de la sección siguiente.

## 5. Nueva evidencia (55 s)
**Qué decir:**
- CodeQL, con la misma versión antes y después, pasó de 9 resultados a 0, y las 7
  alertas quedaron como corregidas.
- Semgrep dio 22 hallazgos antes y 22 después: la corrección no agrega nada.
- La prueba de regresión pasa los 17 casos, y recalcular las métricas de todas las
  corridas da exactamente lo mismo: la corrección no cambió resultados.

**Qué mostrar:** la página de code scanning con las alertas cerradas, y los
[PR #6](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/6)
y [PR #7](https://github.com/Lanch3ros/fdsi-gp06-secure-conversational-memory-lab5/pull/7).

## 6. Limitaciones (45 s)
**Qué decir:**
- No hay staging ni servicio web, así que el DAST fue local contra Ollama y solo
  pudo revisar su portada.
- Ninguna herramienta detectó la falla central del proyecto, la recuperación de
  memorias de otros usuarios (la mide nuestro experimento T02), ni la clave HMAC
  fija.
- Siguen abiertos F-01, F-02, F-04, F-05 y F-06, y `main` no tiene protección de
  rama: un check fallido no bloquea el merge.

## Comandos de la demostración en vivo
Desde la raíz del repositorio, con `make setup` ya hecho:

```bash
.venv/bin/python -m pytest -q tests/test_rutas_experimentos.py
```

Resultado esperado: `17 passed`.

```bash
.venv/bin/python experiments/compute_metrics.py ../fuera
```

Resultado esperado: `nombre no valido, sale de …/evidence/runs: '../fuera'`, con
código de salida 1 y sin leer ni escribir nada fuera de `evidence/`.

## Antes de presentar
- Correr `make setup` y los dos comandos una vez, para no esperar en vivo.
- Dejar abiertas la página de code scanning, los PR #6 y #7 y `SECURITY.md`.

## Preguntas probables
- **¿Por qué no hay DAST contra un staging HTTPS?** `memlab` es una herramienta de
  línea de comandos. El enunciado permite un baseline local con Docker, y se escaneó
  la única superficie HTTP del sistema: la API de Ollama.
- **¿Por qué no actualizaron `chromadb`?** Sus cuatro avisos no tienen versión
  corregida y son del servidor HTTP de ChromaDB, que no usamos. Cambiar la versión,
  además, alteraría las corridas oficiales del proyecto.
- **¿Cómo saben que la corrección no cambió los resultados del proyecto?** No se
  tocó `src/memlab`, y `make metrics` recalculó todas las corridas con resultados
  idénticos a los versionados.
- **¿Por qué F-05 sigue abierto si es de riesgo medio?** La corrección del punto 7
  pedía una solución pequeña y rastreable, y elegimos la que tenía alertas de CodeQL
  para reescanear. F-05 queda como la siguiente.
- **¿Qué aprendieron de la revisión de código?** Que una corrección confirmada por
  las herramientas puede tener huecos. La revisión automática hizo 5 observaciones
  en los PR #4 a #7, todas válidas: dos sobre enlaces simbólicos, que el reescaneo
  no veía, y tres sobre el script de validación.
