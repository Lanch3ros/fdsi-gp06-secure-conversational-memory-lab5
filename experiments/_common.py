"""Utilidades compartidas por los runners de experimentos."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from memlab.config import Profile  # noqa: E402


def git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "sin-git"


def child_path(base: Path, name: str) -> Path:
    """`base / name`, solo si `name` queda directamente dentro de `base`.

    Los nombres de corrida y los perfiles llegan de la linea de comandos (F-07 y
    F-08, CodeQL py/path-injection). Se rechaza `..`, una ruta absoluta, una
    subcarpeta o un enlace simbolico que apunte fuera (F-11): realpath resuelve
    los enlaces antes de comprobar el prefijo. Resolver la ruta y comprobar su
    prefijo es la validacion que CodeQL reconoce para esa regla. La base tampoco
    puede ser ni atravesar un enlace: realpath la moveria fuera de evidence/ y el
    prefijo dejaria de proteger.
    """
    root = os.path.realpath(base)
    if root != os.path.abspath(base):
        raise SystemExit(f"carpeta base no valida, es o atraviesa un enlace simbolico: {base}")
    path = os.path.realpath(os.path.join(root, name))
    if not path.startswith(root + os.sep):
        raise SystemExit(f"nombre no valido, sale de {base}: {name!r}")
    if os.path.dirname(path) != root:
        raise SystemExit(f"nombre no valido, no es hijo directo de {base}: {name!r}")
    return Path(path)


def new_run_dir(test_id: str, profile: str, evidence_dir: Path | None = None) -> Path:
    # El perfil se valida antes de tocar el disco (F-08): con un valor que no sea
    # unsecure o secure no se crea ninguna carpeta.
    profile = Profile(profile).value
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = evidence_dir or (REPO / "evidence" / "runs")
    run_dir = child_path(base, f"{stamp}-{test_id}-{profile}-{git_sha()}")
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def manifest(test_id: str, settings, fingerprint: dict, extra: dict | None = None) -> dict:
    """Todo lo necesario para repetir la corrida en otra maquina."""
    return {
        "test_id": test_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(),
        "profile": settings.profile.value,
        "llm_backend": settings.llm_backend.value,
        "model": fingerprint,
        "seed": settings.seed,
        "temperature": settings.temperature,
        "num_predict": settings.num_predict,
        "retrieval_k": settings.retrieval_k,
        "tenant_id": settings.tenant_id,
        "python": sys.version.split()[0],
        **(extra or {}),
    }


def reset_lab(data_dir: Path) -> None:
    import shutil

    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
