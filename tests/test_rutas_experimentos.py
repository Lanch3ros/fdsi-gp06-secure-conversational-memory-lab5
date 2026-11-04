"""Prueba de regresion de F-07 y F-08 (Lab 05, punto 7).

CodeQL marco py/path-injection en experiments/: el nombre de la corrida de
compute_metrics.py y el perfil de los runners llegaban de la linea de comandos
y se usaban para armar rutas sin validarlos. Con `../`, una ruta absoluta o un
perfil inexistente se leia, se escribia o se creaba algo fuera de evidence/.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest

import _common
import compute_metrics

VALIDA = "20261103T000000Z-T04-secure-abc1234"

# Nombres de corrida que no son una carpeta directa de evidence/runs/.
NOMBRES_FUERA = {
    "relativo": lambda tmp: "../fuera",
    "absoluto": lambda tmp: str(tmp / "evidence" / "fuera"),
    "subcarpeta": lambda tmp: "sub/corrida",
    "padre": lambda tmp: "..",
    "vacio": lambda tmp: "",
}


def _corrida_falsa(carpeta):
    carpeta.mkdir(parents=True)
    (carpeta / "results.json").write_text(json.dumps({"test_id": "T04"}), encoding="utf-8")
    (carpeta / "manifest.json").write_text(json.dumps({}), encoding="utf-8")


@pytest.fixture
def evidencia(tmp_path, monkeypatch):
    """evidence/ en un directorio temporal: una corrida valida y dos que no lo son."""
    runs = tmp_path / "evidence" / "runs"
    metrics = tmp_path / "evidence" / "metrics"
    for carpeta in (runs / VALIDA, runs / "sub" / "corrida", tmp_path / "evidence" / "fuera"):
        _corrida_falsa(carpeta)
    monkeypatch.setattr(compute_metrics, "RUNS", runs)
    monkeypatch.setattr(compute_metrics, "METRICS", metrics)
    # El calculo de T04 no importa aqui: solo las rutas que se leen y se escriben.
    monkeypatch.setattr(compute_metrics, "metrics_t04", lambda results, manifest: {"warnings": []})
    return tmp_path, metrics


@pytest.mark.parametrize("caso", sorted(NOMBRES_FUERA))
def test_compute_metrics_rechaza_nombres_que_salen_de_runs(evidencia, caso):
    tmp, metrics = evidencia
    with pytest.raises(SystemExit, match="nombre no valido"):
        compute_metrics.compute(NOMBRES_FUERA[caso](tmp))
    assert not (tmp / "evidence" / "fuera.json").exists()
    assert not metrics.exists()


def test_compute_metrics_acepta_una_corrida_de_runs(evidencia):
    _, metrics = evidencia
    out = compute_metrics.compute(VALIDA)
    assert out["run"] == VALIDA
    assert (metrics / f"{VALIDA}.json").is_file()


# F-11 (revision de Codex en el PR #6): una comprobacion solo de texto deja pasar
# un enlace simbolico que esta dentro de la carpeta pero apunta fuera.
def test_compute_metrics_no_lee_a_traves_de_un_enlace_en_runs(evidencia):
    tmp, metrics = evidencia
    (tmp / "evidence" / "runs" / "enlace").symlink_to(tmp / "evidence" / "fuera")
    with pytest.raises(SystemExit, match="nombre no valido"):
        compute_metrics.compute("enlace")
    assert not metrics.exists()


def test_compute_metrics_no_escribe_a_traves_de_un_enlace_en_metrics(evidencia):
    tmp, metrics = evidencia
    metrics.mkdir()
    victima = tmp / "evidence" / "fuera" / "victima.json"
    victima.write_text("original", encoding="utf-8")
    (metrics / f"{VALIDA}.json").symlink_to(victima)
    with pytest.raises(SystemExit, match="nombre no valido"):
        compute_metrics.compute(VALIDA)
    assert victima.read_text(encoding="utf-8") == "original"


@pytest.mark.parametrize("perfil", ["secur", "../../../fuera", "/fuera"])
def test_new_run_dir_rechaza_perfiles_no_validos(tmp_path, perfil):
    with pytest.raises(ValueError):
        _common.new_run_dir("T02", perfil, evidence_dir=tmp_path / "runs")
    assert list(tmp_path.iterdir()) == []


def test_new_run_dir_crea_la_corrida_dentro_de_runs(tmp_path):
    base = tmp_path / "runs"
    run_dir = _common.new_run_dir("T02", "secure", evidence_dir=base)
    assert run_dir.parent == base
    assert run_dir.is_dir()
    assert "-T02-secure-" in run_dir.name


@pytest.mark.parametrize("runner", ["run_t02", "run_t04", "run_t05"])
def test_runner_con_perfil_invalido_no_crea_carpetas(tmp_path, monkeypatch, runner):
    """El caso de `make t02 PROFILE=secur`: antes dejaba una carpeta en evidence/runs/."""
    modulo = importlib.import_module(runner)
    monkeypatch.setattr(_common, "REPO", tmp_path)
    monkeypatch.setattr(sys, "argv", [f"{runner}.py", "--profile", "secur"])
    with pytest.raises(ValueError):
        modulo.main()
    assert not (tmp_path / "evidence").exists()
