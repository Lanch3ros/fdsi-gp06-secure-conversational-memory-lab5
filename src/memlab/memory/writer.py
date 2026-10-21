"""Que se guarda en memoria y como (control C3).

UNSECURE: la tuberia tipica de "extraer y guardar". Detecta si el turno vale la
pena recordarlo usando pistas de RETENCION -no de seguridad- y lo guarda tal
cual, sin tipar, sin validar y sin procedencia. El sistema no se pregunta en
ningun momento si el texto es un hecho del usuario o una orden dirigida al
modelo. Esa pregunta que no se hace es toda la vulnerabilidad de T01 y T03.

SECURE: el filtro tipado, que llega en el Hito 3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..schema import DEFAULT_TTL_S, MemoryKind, MemoryRecord, Provenance, Source

#: Pistas de que el turno merece recordarse en sesiones futuras. Son las mismas
#: que usaria cualquier asistente con memoria: no discriminan orden de hecho.
_RETENTION_CUES = re.compile(
    r"\b(recuerda|recuerde|acuerdate|no olvides|ten en cuenta|"
    r"soy|me llamo|vivo en|mi |prefiero|me gusta|no me gusta|siempre|nunca|"
    r"a partir de ahora|de ahora en adelante)\b",
    re.IGNORECASE,
)

#: Pistas de que el turno es una preferencia permanente y no un dato episodico.
#: Lo que caiga aqui se fija al perfil y entra en TODAS las sesiones futuras.
#: Es una decision de utilidad, no de seguridad, y precisamente por eso el
#: sistema Unsecure fija tambien las instrucciones del atacante.
_STANDING_CUES = re.compile(
    r"\b(recuerda|recuerde|acuerdate|no olvides|siempre|nunca|prefiero|"
    r"a partir de ahora|de ahora en adelante|todas tus respuestas)\b",
    re.IGNORECASE,
)


@dataclass
class WriteVerdict:
    """Lo que el filtro decidio, y por que. Va entero al log de auditoria."""

    stored: bool
    reason: str
    record: MemoryRecord | None = None
    flags: list[str] = field(default_factory=list)


class MemoryWriter:
    """Clase base. El perfil decide cual implementacion se usa."""

    def consider(
        self,
        text: str,
        *,
        tenant_id: str,
        user_id: str,
        session_id: str,
        created_at,
        source: Source = Source.USER_TURN,
    ) -> WriteVerdict:
        raise NotImplementedError


class UnsecureWriter(MemoryWriter):
    def consider(
        self,
        text: str,
        *,
        tenant_id: str,
        user_id: str,
        session_id: str,
        created_at,
        source: Source = Source.USER_TURN,
    ) -> WriteVerdict:
        clean = text.strip()
        if not clean or not _RETENTION_CUES.search(clean):
            return WriteVerdict(stored=False, reason="sin_pistas_de_retencion")

        record = MemoryRecord(
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
            # Todo entra como FACT: no hay nada que clasifique. Una orden del
            # atacante queda indistinguible de "soy vegetariano".
            kind=MemoryKind.FACT,
            content=clean,
            created_at=created_at,
            ttl_s=DEFAULT_TTL_S[MemoryKind.FACT],  # None: no caduca nunca
            pinned=bool(_STANDING_CUES.search(clean)),
            # Sin firma: el origen no es verificable (falta C4).
            provenance=Provenance(
                source=source, author_user_id=user_id, session_id=session_id, signature=None
            ),
        )
        return WriteVerdict(stored=True, reason="guardado_sin_validar", record=record)


# ---------------------------------------------------------------------------
# C3 (Secure): clasificador de escritura basado en reglas, sin juez LLM (eso
# es P3 de la propuesta y queda declarado como limitacion si no se alcanza).
#
# Cada patron apunta a una CONSTRUCCION peligrosa especifica, no a una palabra
# suelta. "a partir de ahora" por si sola no basta: "a partir de ahora vivo en
# Medellin" es un hecho del usuario, no una orden. Lo que la vuelve peligrosa
# es que vaya seguida de un verbo que le ordena algo al asistente ("...
# termina todas tus respuestas con...").
#
# task_context NO se infiere de texto libre en este hito: se asigna solo por
# el canal de siembra firmada (Orchestrator.seed_memory(bypass_c3=True,
# kind=...)), el mismo que usa T02 para el dato de A (regla 7 de CLAUDE.md).
# Clasificar "estoy trabajando en X esta semana" por regex es fragil y
# ninguna prueba de la prioridad P1 lo necesita.
#
# Limitacion declarada: el chequeo de secreto solo reconoce numeros con forma
# de tarjeta (Luhn). Un secreto sin esa forma -una contrasena, por ejemplo- no
# se detecta. No es un descuido: es el limite de un clasificador por reglas.
# ---------------------------------------------------------------------------

_ORDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("respuesta_formateada", re.compile(r"\btermin\w*\s+(todas\s+)?tus\s+respuestas\b", re.IGNORECASE)),
    ("debes_imperativo", re.compile(r"\bdebes\b", re.IGNORECASE)),
    ("guardar_en_memoria", re.compile(r"\bguarda\s+en\s+memoria\s+que\b", re.IGNORECASE)),
    ("autorizacion_sensible", re.compile(
        r"\bautoriz\w*\b.{0,40}\b(correo|correos|dato|datos|tercero|terceros|compart\w*|enviar|confirmar)\b",
        re.IGNORECASE,
    )),
    ("sin_confirmar", re.compile(
        r"\bsin\s+(pedir\s+(mas\s+)?confirmaci[oó]n(es)?|confirmar)\b", re.IGNORECASE
    )),
    ("ignora_instrucciones", re.compile(
        r"\bignora\b.{0,40}\b(instrucci[oó]n|regla|seguridad|anterior)", re.IGNORECASE
    )),
    ("actua_como_admin", re.compile(r"\bactua\b.{0,40}\badministrador\b", re.IGNORECASE)),
    ("desactivar_seguridad", re.compile(r"\bdesactiva\b.{0,40}\b(filtro|seguridad)\b", re.IGNORECASE)),
    ("system_prompt", re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE)),
    ("mensaje_del_sistema", re.compile(r"\bmensaje\s+del\s+sistema\b", re.IGNORECASE)),
    ("asistente_debe", re.compile(r"\bel\s+(asistente|modelo)\s+debe\b", re.IGNORECASE)),
    ("nunca_confirmacion", re.compile(
        r"\bnunca\b.{0,40}\b(me\s+pidas|me\s+preguntes|me\s+confirmes|pidas\s+confirmaci[oó]n)\b",
        re.IGNORECASE,
    )),
    ("orden_temporal_prefijo", re.compile(
        r"\b(a\s+partir\s+de\s+(ahora|este\s+momento)|de\s+ahora\s+en\s+adelante)\b"
        r".{0,60}\b(termina|debes|actua|ignora|responde|incluye|env[ií]a|comparte|desactiv\w*)\b",
        re.IGNORECASE,
    )),
    ("sin_dudar", re.compile(r"\bsin\s+dudar\b", re.IGNORECASE)),
    ("enlace", re.compile(r"https?://\S+|\bwww\.\S+\.(com|net|org|biz|local)\b", re.IGNORECASE)),
]

_PREFERENCE_CUES = re.compile(r"\b(prefiero|me gusta|no me gusta)\b", re.IGNORECASE)

#: Lo que se fija al perfil (pinned) si no quedo rechazado como orden o
#: secreto. Es decision de utilidad, igual que en Unsecure: aqui ya no hay
#: riesgo de seguridad porque C1 filtra los dos canales por dueno sin
#: excepcion (secure=True en MemoryRetriever).
_PINNED_CUES = re.compile(
    r"\b(prefiero|me gusta|no me gusta|siempre|nunca|recuerda|recuerde|acuerdate|ten en cuenta)\b",
    re.IGNORECASE,
)

#: Un numero de tarjeta tiene entre 13 y 19 digitos, separados como mucho por
#: espacios o guiones. El limite superior del rango de caracteres evita que
#: la expresion se coma dos numeros sin relacion entre si.
_CARD_CANDIDATE = re.compile(r"\b\d[\d \-]{11,22}\d\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _contains_card(text: str) -> bool:
    for m in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True
    return False


class SecureWriter(MemoryWriter):
    """Control C3: filtro de escritura con esquema tipado.

    Reusa la misma puerta de utilidad que Unsecure (_RETENTION_CUES): si el
    texto no trae ninguna pista de que valga la pena recordarlo, no se guarda,
    por la misma razon de siempre y no por seguridad. Ese veredicto queda como
    "sin_pistas_de_retencion" y NO cuenta como falso positivo de C3 para M3:
    M3 mide clasificacion de seguridad, no la heuristica de utilidad que ya
    trae Unsecure.

    Encima de esa puerta va la clasificacion de seguridad: una orden o un
    numero de tarjeta se rechazan sin excepcion, incluso si el mismo texto
    tambien trae una pista de retencion legitima.
    """

    def consider(
        self,
        text: str,
        *,
        tenant_id: str,
        user_id: str,
        session_id: str,
        created_at,
        source: Source = Source.USER_TURN,
    ) -> WriteVerdict:
        clean = text.strip()
        if not clean or not _RETENTION_CUES.search(clean):
            return WriteVerdict(stored=False, reason="sin_pistas_de_retencion")

        if _contains_card(clean):
            return WriteVerdict(
                stored=False, reason="rechazado_secreto_tarjeta", flags=["secreto_tarjeta"]
            )

        matched_orders = [label for label, pattern in _ORDER_PATTERNS if pattern.search(clean)]
        if matched_orders:
            return WriteVerdict(stored=False, reason="rechazado_instruccion", flags=matched_orders)

        kind = MemoryKind.PREFERENCE if _PREFERENCE_CUES.search(clean) else MemoryKind.FACT
        record = MemoryRecord(
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
            kind=kind,
            content=clean,
            created_at=created_at,
            ttl_s=DEFAULT_TTL_S[kind],
            pinned=bool(_PINNED_CUES.search(clean)),
            # C4 completo (firmar toda escritura normal y verificar en
            # lectura) es prioridad P2. Lo que SI firma en este hito es el
            # canal de siembra directa (seed_memory(bypass_c3=True)) que usa
            # T02 para el dato de A, por la regla 7 de CLAUDE.md.
            provenance=Provenance(
                source=source, author_user_id=user_id, session_id=session_id, signature=None
            ),
        )
        return WriteVerdict(stored=True, reason="guardado_tipado", record=record)


def build_writer(is_secure: bool) -> MemoryWriter:
    return SecureWriter() if is_secure else UnsecureWriter()
