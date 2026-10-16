"""Tiempo de vida y borrado verificable (control C5).

La purga es una funcion pura que recibe el `now` que le den. APScheduler solo la
invoca en produccion. Asi T04 puede adelantar el reloj del laboratorio sin
depender de que un hilo de fondo vea el mismo reloj congelado.

SECURE: `forget` y `purge_expired` borran en las tres capas -fila (DELETE real,
no logico), embedding y cache de sesion- y dejan una `deletion_proof` firmada
con HMAC en el log de auditoria. La prueba usa HMAC y no un SHA plano sobre el
contenido: un hash publico de un dato corto y de baja entropia (una direccion,
un numero de tarjeta) se invierte por fuerza bruta en segundos, y el log de
solo-agregado terminaria siendo una copia recuperable de lo que se prometio
borrar (ver la nota de diseno en provenance.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..provenance import deletion_proof
from .store import MemoryStore

if TYPE_CHECKING:
    from ..audit import AuditLog


@dataclass
class PurgeReport:
    checked: int = 0
    expired: int = 0
    purged_rows: list[str] = field(default_factory=list)
    purged_embeddings: list[str] = field(default_factory=list)


@dataclass
class DeletionResult:
    record_id: str
    row_gone: bool
    embedding_gone: bool
    cache_gone: bool

    @property
    def complete(self) -> bool:
        return self.row_gone and self.embedding_gone and self.cache_gone


class Lifecycle:
    def __init__(
        self,
        store: MemoryStore,
        *,
        is_secure: bool,
        audit: "AuditLog | None" = None,
        hmac_key: bytes = b"",
    ) -> None:
        self.store = store
        self.is_secure = is_secure
        self.audit = audit
        self.hmac_key = hmac_key

    def forget(self, record_id: str, *, session_id: str | None = None) -> DeletionResult:
        """Atiende el "olvida lo que sabes sobre X".

        UNSECURE: borrado logico de la fila. El embedding sigue en el indice y la
        cache de la sesion tambien, asi que el dato se vuelve a recuperar.
        SECURE:   borrado real en las tres capas, mas prueba de borrado.
        """
        if not self.is_secure:
            self.store.soft_delete_row(record_id)
            return DeletionResult(
                record_id=record_id,
                row_gone=not self.store.row_exists(record_id),
                embedding_gone=not self.store.embedding_exists(record_id),
                cache_gone=False,
            )

        record = self.store.get(record_id)
        content = record.content if record is not None else ""

        self.store.hard_delete_row(record_id)
        self.store.delete_embedding(record_id)
        self.store.purge_content_from_cache(content)

        result = DeletionResult(
            record_id=record_id,
            row_gone=not self.store.row_exists(record_id),
            embedding_gone=not self.store.embedding_exists(record_id),
            cache_gone=not self.store.cache_contains(content),
        )
        self._emit_proof(record_id, content, reason="forget")
        return result

    def purge_expired(self, now: datetime) -> PurgeReport:
        report = PurgeReport()
        for rec in self.store.all_records():
            report.checked += 1
            if not rec.is_expired(now):
                continue
            report.expired += 1
            if not self.is_secure:
                # Sin purga: el dato vencido sigue disponible (T04, Unsecure).
                continue

            self.store.hard_delete_row(rec.record_id)
            self.store.delete_embedding(rec.record_id)
            self.store.purge_content_from_cache(rec.content)
            report.purged_rows.append(rec.record_id)
            report.purged_embeddings.append(rec.record_id)
            self._emit_proof(rec.record_id, rec.content, reason="ttl_expirado")
        return report

    def _emit_proof(self, record_id: str, content: str, *, reason: str) -> None:
        if self.audit is None:
            return
        proof = deletion_proof(
            record_id,
            content,
            self.hmac_key,
            layers=["row", "embedding", "session_cache"],
            ts=datetime.now(timezone.utc).isoformat(),
        )
        self.audit.emit("deletion_proof", reason=reason, **proof)
