#!/bin/bash
# Validacion manual del Lab 05, punto 6: la API de Ollama no exige autenticacion.
# Solo peticiones de lectura (GET /api/version y GET /api/tags) contra la
# instancia local del laboratorio. No toca rutas que modifican modelos.
# Uso (macOS): bash validar-ollama.sh <archivo-de-salida>
set -u
OUT="$1"
BASE=http://127.0.0.1:11434
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
LANIP=$(ipconfig getifaddr "$IFACE" 2>/dev/null || true)

{
  echo "# Validacion manual (Lab 05, punto 6): API de Ollama sin autenticacion"
  echo "# Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Solo peticiones de lectura contra la instancia local del laboratorio."
  echo
  echo "## Donde escucha Ollama"
  echo '$ lsof -nP -iTCP:11434 -sTCP:LISTEN   (sin las columnas de usuario y dispositivo)'
  lsof -nP -iTCP:11434 -sTCP:LISTEN | awk '{print $1, $2, $5, $8, $9, $10}'
  echo
  echo "## P1. GET /api/version sin credenciales, desde el propio equipo"
  echo "\$ curl -sSi $BASE/api/version"
  curl -sSi --max-time 5 "$BASE/api/version"
  echo; echo
  echo "## P2. GET /api/tags sin credenciales (lista de modelos, solo lectura)"
  echo "\$ curl -sSi $BASE/api/tags"
  curl -sSi --max-time 5 "$BASE/api/tags"
  echo; echo
  echo "## P3. GET /api/version por la IP de red del equipo"
  if [ -n "$LANIP" ]; then
    echo "\$ curl -sSi http://$LANIP:11434/api/version"
    curl -sSi --max-time 5 "http://$LANIP:11434/api/version"
    echo "(curl termino con codigo $?)"
  else
    echo "(sin interfaz de red activa: no se pudo probar)"
  fi
  echo
  echo "## P4. GET /api/version con el Origin de otro sitio, como lo enviaria un navegador"
  echo "\$ curl -sSi -H 'Origin: http://evil.local' $BASE/api/version"
  curl -sSi --max-time 5 -H 'Origin: http://evil.local' "$BASE/api/version"
  echo; echo
  echo "## P5. GET /api/version con un Origin local (control)"
  echo "\$ curl -sSi -H 'Origin: http://localhost:3000' $BASE/api/version"
  curl -sSi --max-time 5 -H 'Origin: http://localhost:3000' "$BASE/api/version"
  echo
} 2>&1 | tr -d '\r' > "$OUT"

# La IP de red local no se publica en la evidencia
if [ -n "$LANIP" ]; then
  ESC=$(printf '%s' "$LANIP" | sed 's/\./\\./g')
  sed -i '' "s/$ESC/<IP-de-red-local>/g" "$OUT"
fi
echo "listo: $OUT"
