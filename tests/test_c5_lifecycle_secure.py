"""C5 en Secure: tiempo de vida y borrado verificable en las tres capas.

El tiempo se mueve con FrozenClock (nunca freezegun, ver clock.py): asi T04
puede adelantar el reloj del laboratorio sin depender de un hilo de fondo que
no lo vea congelado.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from memlab.audit import AuditLog
from memlab.clock import FrozenClock
from memlab.config import LLMBackend, Profile, Settings
from memlab.orchestrator import Orchestrator
from memlab.schema import MemoryKind


def _secure_orch(tmp_path, clock):
    settings = Settings.from_env(
        profile=Profile.SECURE, llm_backend=LLMBackend.STUB, data_dir=tmp_path / "data"
    )
    audit = AuditLog(tmp_path / "audit.jsonl", run_id=uuid.uuid4().hex[:8])
    return Orchestrator(settings, audit, clock=clock)


def test_un_task_context_vencido_no_se_recupera_tras_48h(tmp_path):
    clock = FrozenClock(datetime(2026, 10, 16, tzinfo=timezone.utc))
    orch = _secure_orch(tmp_path, clock)
    rid = orch.seed_memory(
        "B", "t04", "Esta semana estoy ayudando con el cierre del reporte trimestral.",
        bypass_c3=True, kind=MemoryKind.TASK_CONTEXT, pinned=True,
    )
    assert orch.store.get(rid).ttl_s == 24 * 3600

    antes = orch.retriever.retrieve("hola", tenant_id="eci", user_id="B", now=clock.now())
    assert any(r.record.record_id == rid for r in antes)

    clock.advance(hours=48)
    despues = orch.retriever.retrieve("hola", tenant_id="eci", user_id="B", now=clock.now())
    assert not any(r.record.record_id == rid for r in despues), (
        "un task_context vencido no debe volver por ningun canal (C5 en lectura)"
    )


def test_purge_expired_borra_fila_y_embedding_y_deja_prueba_de_borrado(tmp_path):
    clock = FrozenClock(datetime(2026, 10, 16, tzinfo=timezone.utc))
    orch = _secure_orch(tmp_path, clock)
    rid = orch.seed_memory(
        "B", "t04", "Esta semana estoy ayudando con el cierre del reporte trimestral.",
        bypass_c3=True, kind=MemoryKind.TASK_CONTEXT, pinned=True,
    )
    clock.advance(hours=48)

    report = orch.lifecycle.purge_expired(clock.now())
    assert rid in report.purged_rows
    assert rid in report.purged_embeddings
    assert not orch.store.row_exists(rid)
    assert not orch.store.embedding_exists(rid)

    proofs = [e for e in orch.audit.read() if e["event"] == "deletion_proof"]
    assert proofs, "la purga debe dejar una deletion_proof en el log"
    proof = proofs[-1]
    assert proof["record_id"] == rid
    assert "content_hmac" in proof and proof["content_hmac"], "la prueba debe ser HMAC, no SHA plano"
    assert set(proof["layers"]) == {"row", "embedding", "session_cache"}


def test_forget_borra_las_tres_capas_incluida_la_cache_de_otras_sesiones(tmp_path):
    """La cache se llena desde la sesion de quien PREGUNTA, no solo desde la
    de quien escribio: forget tiene que limpiar por contenido, no solo por el
    session_id de origen."""
    clock = FrozenClock(datetime(2026, 10, 16, tzinfo=timezone.utc))
    orch = _secure_orch(tmp_path, clock)
    rid = orch.seed_memory(
        "B", "t05-origen", "Mi direccion de entrega es Carrera 9 # 10-20.",
        bypass_c3=True, pinned=True,
    )
    orch.turn("B", "t05-otra-sesion", "¿Cual es mi direccion?")
    assert orch.store.cache_contains("Carrera 9 # 10-20")

    result = orch.lifecycle.forget(rid)
    assert result.complete
    assert not orch.store.row_exists(rid)
    assert not orch.store.embedding_exists(rid)
    assert not orch.store.cache_contains("Carrera 9 # 10-20")

    for _ in range(10):
        retrieved = orch.retriever.retrieve(
            "¿Cual es mi direccion?", tenant_id="eci", user_id="B", now=clock.now()
        )
        assert not any(r.record.record_id == rid for r in retrieved)


def test_unsecure_no_implementa_purga_el_vencido_sigue_disponible(tmp_path):
    """Regresion de la linea base: T04 Unsecure debe dar 10/10, no 0/10."""
    clock = FrozenClock(datetime(2026, 10, 16, tzinfo=timezone.utc))
    settings = Settings.from_env(
        profile=Profile.UNSECURE, llm_backend=LLMBackend.STUB, data_dir=tmp_path / "data"
    )
    audit = AuditLog(tmp_path / "audit.jsonl", run_id=uuid.uuid4().hex[:8])
    orch = Orchestrator(settings, audit, clock=clock)

    orch.turn("B", "s1", "Recuerda que a partir de ahora trabajo en el turno de la tarde.")
    clock.advance(hours=48)
    report = orch.lifecycle.purge_expired(clock.now())
    assert report.purged_rows == [], "Unsecure no purga nada: no hay control C5"
