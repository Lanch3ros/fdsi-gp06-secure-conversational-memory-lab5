"""C3 en Secure: filtro de escritura basado en reglas.

M3 completo (60 candidatos, con intervalo de Wilson) es prioridad P2. Estas
pruebas verifican la tuberia con el backend stub: que el filtro rechace lo
peligroso, deje pasar lo normal -incluido lo que PARECE una orden sin serlo-,
y que el motivo quede en el veredicto para que M3 pueda distinguir despues un
rechazo de seguridad de un simple "sin pistas de retencion".
"""

from __future__ import annotations

from datasets_hito3 import M3_CANDIDATES

from memlab.config import Profile


def test_las_ordenes_se_rechazan(lab):
    orch = lab(Profile.SECURE)
    ordenes = [c["text"] for c in M3_CANDIDATES if c["subtype"] == "orden"]
    assert ordenes
    for text in ordenes:
        rid = orch.seed_memory("tester", "m3", text)
        assert rid is None, f"debio rechazarse como orden: {text}"


def test_las_tarjetas_con_luhn_valido_se_rechazan(lab):
    orch = lab(Profile.SECURE)
    tarjetas = [
        c["text"] for c in M3_CANDIDATES
        if c["subtype"] == "secreto" and "tarjeta" in c["text"].lower()
    ]
    assert tarjetas
    for text in tarjetas:
        rid = orch.seed_memory("tester", "m3", text)
        assert rid is None, f"debio rechazarse como secreto: {text}"


def test_las_inyecciones_disfrazadas_se_rechazan(lab):
    orch = lab(Profile.SECURE)
    disfrazadas = [c["text"] for c in M3_CANDIDATES if c["subtype"] == "inyeccion_disfrazada"]
    assert disfrazadas
    for text in disfrazadas:
        rid = orch.seed_memory("tester", "m3", text)
        assert rid is None, f"debio rechazarse como inyeccion disfrazada: {text}"


def test_lo_normal_no_se_rechaza_por_seguridad_aunque_parezca_una_orden(lab):
    """El caso que da el plan: 'prefiero que siempre me respondas corto' no es
    una orden. Si C3 la rechazara, bastaria con rechazar cualquier frase con
    'siempre' para aprobar M3, y eso no demuestra nada (ver writer.py)."""
    orch = lab(Profile.SECURE)
    parecen_ordenes = [c["text"] for c in M3_CANDIDATES if c["subtype"] == "parece_orden"]
    assert parecen_ordenes
    for text in parecen_ordenes:
        rid = orch.seed_memory("tester", "m3", text)
        assert rid is not None, f"no debio rechazarse por seguridad: {text}"


def test_ningun_normal_se_rechaza_por_un_motivo_de_seguridad(lab):
    """Un normal SI puede quedar sin guardar por falta de pistas de retencion
    (igual que en Unsecure, regla de utilidad, no de seguridad). Lo que no
    puede pasar es que se rechace como 'rechazado_instruccion' o
    'rechazado_secreto_tarjeta': eso seria un falso positivo de C3."""
    orch = lab(Profile.SECURE)
    normales = [c["text"] for c in M3_CANDIDATES if c["label"] == "normal"]
    for text in normales:
        rid = orch.seed_memory("tester", "m3", text)
        if rid is None:
            ultimo = [e for e in orch.audit.read() if e["event"] == "seed_rejected"][-1]
            assert ultimo["reason"] == "sin_pistas_de_retencion", (
                f"falso positivo de seguridad sobre un texto normal: {text!r} -> {ultimo['reason']}"
            )
