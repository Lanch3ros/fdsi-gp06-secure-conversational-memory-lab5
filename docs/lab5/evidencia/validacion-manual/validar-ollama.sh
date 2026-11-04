#!/bin/bash
# Validacion manual del Lab 05, punto 6: la API de Ollama no exige autenticacion.
# Solo peticiones de lectura (GET /api/version y GET /api/tags) contra la
# instancia local del laboratorio. No toca rutas que modifican modelos.
# Uso (macOS): bash validar-ollama.sh <archivo-de-salida>
# Sirve como prueba de regresion: compara cada respuesta con la esperada y
# termina con codigo 1 si alguna no coincide o si no se pudo comprobar.
set -u
OUT="$1"
BASE=http://127.0.0.1:11434
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
LANIP=$(ipconfig getifaddr "$IFACE" 2>/dev/null || true)
FALLAS=0

# Sin archivo de salida no hay evidencia: se falla antes de probar nada.
if ! : > "$OUT"; then
  echo "FALLA: no se puede escribir el archivo de salida: $OUT" >&2
  exit 1
fi

# probar <id> <esperado> <descripcion> <url> [cabecera] [encabezado-esperado]
# <esperado> es un codigo HTTP, o "sin-conexion" si no debe poder conectarse.
# [encabezado-esperado] es una linea que tiene que aparecer en la respuesta.
probar() {
  local id="$1" esperado="$2" desc="$3" url="$4" cabecera="${5:-}" encabezado="${6:-}"
  local args=(-sSi --max-time 5) muestra="curl -sSi"
  if [ -n "$cabecera" ]; then
    args+=(-H "$cabecera")
    muestra="$muestra -H '$cabecera'"
  fi
  echo "## $id. $desc"
  echo "\$ $muestra $url"
  local resp rc obtenido
  resp=$(curl "${args[@]}" "$url" 2>&1)
  rc=$?
  printf '%s\n' "$resp" | tr -d '\r'
  if [ "$rc" -ne 0 ]; then
    obtenido="sin-conexion"
  else
    obtenido=$(printf '%s\n' "$resp" | head -1 | awk '{print $2}')
  fi
  local falta=""
  if [ -n "$encabezado" ] && ! printf '%s\n' "$resp" | tr -d '\r' | grep -qixF "$encabezado"; then
    falta=" sin '$encabezado'"
  fi
  if [ "$obtenido" = "$esperado" ] && [ -z "$falta" ]; then
    echo "=> esperado: $esperado${encabezado:+ con '$encabezado'} | obtenido: $obtenido | OK"
  else
    echo "=> esperado: $esperado${encabezado:+ con '$encabezado'} | obtenido: $obtenido$falta (curl: $rc) | FALLA"
    FALLAS=$((FALLAS + 1))
  fi
  echo
}

# Sin tuberia: el bloque corre en este shell y FALLAS conserva su valor.
{
  echo "# Validacion manual (Lab 05, punto 6): API de Ollama sin autenticacion"
  echo "# Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Solo peticiones de lectura contra la instancia local del laboratorio."
  echo
  echo "## Donde escucha Ollama"
  echo '$ lsof -nP -iTCP:11434 -sTCP:LISTEN   (sin las columnas de usuario y dispositivo)'
  lsof -nP -iTCP:11434 -sTCP:LISTEN | awk '{print $1, $2, $5, $8, $9, $10}'
  echo
  probar P1 200 "GET /api/version sin credenciales, desde el propio equipo" "$BASE/api/version"
  probar P2 200 "GET /api/tags sin credenciales (lista de modelos, solo lectura)" "$BASE/api/tags"
  if [ -n "$LANIP" ]; then
    probar P3 sin-conexion "GET /api/version por la IP de red del equipo" "http://$LANIP:11434/api/version"
  else
    echo "## P3. GET /api/version por la IP de red del equipo"
    echo "=> no se pudo comprobar: no hay interfaz de red activa | FALLA"
    echo
    FALLAS=$((FALLAS + 1))
  fi
  probar P4 403 "GET /api/version con el Origin de otro sitio, como lo enviaria un navegador" "$BASE/api/version" "Origin: http://evil.local"
  probar P5 200 "GET /api/version con un Origin local (control)" "$BASE/api/version" "Origin: http://localhost:3000" "Access-Control-Allow-Origin: http://localhost:3000"
  if [ "$FALLAS" -eq 0 ]; then
    echo "## Resultado: las 5 pruebas dieron lo esperado"
  else
    echo "## Resultado: $FALLAS prueba(s) con un resultado distinto del esperado"
  fi
} > "$OUT" 2>&1

# La IP de red local no se publica en la evidencia
if [ -n "$LANIP" ]; then
  ESC=$(printf '%s' "$LANIP" | sed 's/\./\\./g')
  sed -i '' "s/$ESC/<IP-de-red-local>/g" "$OUT"
fi

if [ "$FALLAS" -eq 0 ]; then
  echo "OK: las 5 pruebas dieron lo esperado ($OUT)"
  exit 0
fi
echo "FALLA: $FALLAS prueba(s) con un resultado distinto del esperado ($OUT)" >&2
exit 1
