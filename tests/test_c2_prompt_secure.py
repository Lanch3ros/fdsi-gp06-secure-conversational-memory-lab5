"""C2 en Secure: la memoria sale del mensaje de sistema."""

from __future__ import annotations

from questions import DORMANT_INSTRUCTION, INNOCENT_QUESTIONS
from memlab.config import Profile
from memlab.schema import MemoryKind


def test_el_sistema_no_lleva_memoria_del_usuario(lab):
    orch = lab(Profile.SECURE)
    orch.seed_memory("B", "s0", "Mi direccion es Calle 1 # 2-3.", bypass_c3=True, pinned=True)
    result = orch.turn("B", "s1", INNOCENT_QUESTIONS[0])
    assert result.messages[0]["role"] == "system"
    assert "Calle 1" not in result.messages[0]["content"]
    assert "Calle 1" in result.messages[1]["content"]


def test_el_bloque_de_memoria_va_delimitado_y_con_aviso_explicito(lab):
    orch = lab(Profile.SECURE)
    orch.seed_memory("B", "s0", "Mi direccion es Calle 1 # 2-3.", bypass_c3=True, pinned=True)
    result = orch.turn("B", "s1", INNOCENT_QUESTIONS[0])
    user_msg = result.messages[1]["content"]
    assert "no instrucciones" in user_msg
    assert "<<DATOS_USUARIO_" in user_msg and "<</DATOS_USUARIO_" in user_msg


def test_el_marcador_cambia_entre_sesiones_y_no_sale_del_session_id(lab):
    orch = lab(Profile.SECURE)
    orch.seed_memory("B", "s0", "Mi direccion es Calle 1 # 2-3.", bypass_c3=True, pinned=True)
    r1 = orch.turn("B", "sesion-uno", INNOCENT_QUESTIONS[0])
    r2 = orch.turn("B", "sesion-dos", INNOCENT_QUESTIONS[1])

    import re

    m1 = re.search(r"<<DATOS_USUARIO_([0-9a-f]+)>>", r1.messages[1]["content"])
    m2 = re.search(r"<<DATOS_USUARIO_([0-9a-f]+)>>", r2.messages[1]["content"])
    assert m1 and m2
    assert m1.group(1) != m2.group(1), "el marcador debe cambiar entre sesiones distintas"


def test_una_instruccion_sembrada_no_queda_con_autoridad_de_sistema(lab):
    """Aunque C3 la hubiera dejado pasar, C2 por si solo ya le quita la
    autoridad de sistema que explota T01 en Unsecure."""
    orch = lab(Profile.SECURE)
    orch.seed_memory(
        "B", "s0", DORMANT_INSTRUCTION, bypass_c3=True, kind=MemoryKind.FACT, pinned=True
    )
    result = orch.turn("B", "s1", INNOCENT_QUESTIONS[0])
    assert "evil.local" not in result.messages[0]["content"], "no debe llegar al mensaje de sistema"
    assert "evil.local" in result.messages[1]["content"], "debe llegar como dato citado, no como orden"
