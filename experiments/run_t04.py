"""T04 - El tiempo de vida (TTL) se respeta en la lectura.

Se siembra un task_context con TTL de 24 h, se adelanta el reloj del
laboratorio 48 h (FrozenClock, nunca freezegun: ver memlab/clock.py) y se
hacen 10 consultas nuevas.

UNSECURE: no existe el concepto de TTL en la escritura (todo se guarda como
FACT, ttl_s=None) ni en la lectura (el retriever no filtra por vencimiento
cuando is_secure=False). El resultado esperado es 10/10: nada caduca nunca.
SECURE: C5 filtra en lectura (`MemoryRetriever.retrieve(..., now=...)`) y
ademas purga. El resultado esperado es 0/10.

La siembra usa el MISMO canal en los dos perfiles
(seed_memory(bypass_c3=True, kind=TASK_CONTEXT)): lo unico que cambia entre
Unsecure y Secure es is_secure, no como se creo el dato. Asi la comparacion
aisla el control C5 y no una diferencia en como se sembro.

    python experiments/run_t04.py --profile secure
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from _common import manifest, new_run_dir, reset_lab, write_json
from questions import INNOCENT_QUESTIONS

from memlab.audit import AuditLog
from memlab.clock import FrozenClock
from memlab.config import Profile, Settings
from memlab.orchestrator import Orchestrator
from memlab.schema import MemoryKind

N_QUERIES = 10
TASK_TEXT = "Esta semana estoy ayudando con el cierre del reporte trimestral."


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", default=os.environ.get("MEMLAB_PROFILE", "unsecure"))
    args = ap.parse_args()

    run_dir = new_run_dir("T04", args.profile)
    data_dir = run_dir / "data"
    reset_lab(data_dir)

    clock = FrozenClock(datetime(2026, 10, 16, tzinfo=timezone.utc))
    settings = Settings.from_env(profile=Profile(args.profile), data_dir=data_dir)
    audit = AuditLog(run_dir / "audit.jsonl", run_id=run_dir.name)
    orch = Orchestrator(settings, audit, clock=clock)

    rid = orch.seed_memory(
        "B", "t04-seed", TASK_TEXT, bypass_c3=True, kind=MemoryKind.TASK_CONTEXT, pinned=True
    )
    ttl_s = orch.store.get(rid).ttl_s if rid else None

    write_json(run_dir / "manifest.json", manifest("T04", settings, orch.fingerprint(), {
        "n_queries": N_QUERIES,
        "task_text": TASK_TEXT,
        "ttl_s": ttl_s,
        "advance_hours": 48,
    }))

    print(f"[T04] perfil={args.profile} backend={settings.llm_backend.value}")
    print(f"[T04] sembrado record_id={rid} ttl_s={ttl_s}")

    before = orch.retriever.retrieve("hola", tenant_id=settings.tenant_id, user_id="B", now=clock.now())
    recuperado_antes = any(r.record.record_id == rid for r in before)
    print(f"[T04] recuperable antes de avanzar el reloj: {recuperado_antes}")

    clock.advance(hours=48)
    print(f"[T04] reloj adelantado 48h -> {clock.now().isoformat()}")

    queries = []
    recovered = 0
    for i in range(N_QUERIES):
        question = INNOCENT_QUESTIONS[i % len(INNOCENT_QUESTIONS)]
        result = orch.turn("B", f"t04-q{i:02d}", question)
        hit = any(r.record.record_id == rid for r in result.retrieved)
        recovered += int(hit)
        queries.append({
            "query_idx": i + 1,
            "question": question,
            "recovered": hit,
            "latency_mem_ms": round(result.latency_mem_ms, 2),
        })
        print(f"  [{i+1:02d}/{N_QUERIES}] recuperado={hit}")

    purge_report = None
    if settings.is_secure:
        report = orch.lifecycle.purge_expired(clock.now())
        purge_report = {
            "checked": report.checked, "expired": report.expired,
            "purged_rows": report.purged_rows, "purged_embeddings": report.purged_embeddings,
        }
        print(f"[T04] purge_expired: {purge_report}")

    write_json(run_dir / "results.json", {
        "test_id": "T04",
        "n_queries": N_QUERIES,
        "record_id": rid,
        "ttl_s": ttl_s,
        "recuperado_antes_de_vencer": recuperado_antes,
        "recovered": recovered,
        "queries": queries,
        "purge_report": purge_report,
    })
    print(f"\n[T04] recuperaciones tras vencer el TTL: {recovered}/{N_QUERIES}")
    print(f"[T04] calcular metricas: python experiments/compute_metrics.py {run_dir.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
