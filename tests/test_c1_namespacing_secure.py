"""C1 en Secure: los dos canales de recuperacion filtran por dueno.

El filtro ya estaba escrito en memory/retriever.py desde el Hito 2, pero
nunca se habia medido con el perfil Secure corriendo de punta a punta
(ver CLAUDE.md, "Estado al 16/10/2026"). Estas pruebas cierran eso.

El dato de A entra por el canal de siembra firmada (bypass_c3=True, regla 7
de CLAUDE.md): si pasara por C3, un numero de tarjeta se rechazaria como
secreto y la prueba no mediria C1, mediria C3.
"""

from __future__ import annotations

from questions import LEGIT_MEMORIES, USER_A_MEMORIES, probe_questions

from memlab.config import Profile


def test_la_siembra_firmada_entra_sin_pasar_por_c3(lab):
    orch = lab(Profile.SECURE)
    for text in USER_A_MEMORIES:
        rid = orch.seed_memory("A", "a1", text, bypass_c3=True)
        assert rid is not None, "C3 no debe intervenir en el canal de siembra firmada"
        record = orch.store.get(rid)
        assert record.provenance.signature is not None, "el dato de A debe quedar firmado (C4)"
        assert record.pinned is False, "episodico: no debe quedar fijado al perfil"


def test_ningun_canal_devuelve_datos_de_otro_usuario(lab):
    orch = lab(Profile.SECURE)
    for text in USER_A_MEMORIES:
        orch.seed_memory("A", "a1", text, bypass_c3=True)
    for i, text in enumerate(LEGIT_MEMORIES):
        orch.seed_memory("B", f"b-prev-{i:02d}", text)

    for probe in probe_questions(10):
        retrieved = orch.retriever.retrieve(probe, tenant_id=orch.settings.tenant_id, user_id="B")
        ajenos = [r for r in retrieved if r.record.user_id != "B"]
        assert not ajenos, f"C1 debe bloquear los dos canales; fugo: {ajenos}"


def test_m2a_fuga_de_recuperacion_es_cero_en_cien_sondeos(lab):
    """C1 se aprueba con M2a = 0 (regla 4 de CLAUDE.md), no con M2b = 0."""
    orch = lab(Profile.SECURE)
    for text in USER_A_MEMORIES:
        orch.seed_memory("A", "a1", text, bypass_c3=True)
    for i, text in enumerate(LEGIT_MEMORIES):
        orch.seed_memory("B", f"b-prev-{i:02d}", text)

    leaks = sum(1 for q in probe_questions(100) if orch.turn("B", "t02-b", q).cross_namespace_hits)
    assert leaks == 0
