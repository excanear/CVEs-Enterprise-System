"""Domain ports (Protocol interfaces) for the Exposure Validation Engine."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from cves_db.types import TenantId

from exposure_validation.domain.entities.validation_job import ValidationJob
from exposure_validation.domain.entities.validation_result import ValidationResult


@runtime_checkable
class ValidationJobRepository(Protocol):
    async def save(self, job: ValidationJob) -> None: ...
    async def get(self, job_id: str) -> ValidationJob | None: ...
    async def list_by_tenant(
        self, tenant_id: TenantId, limit: int, offset: int
    ) -> list[ValidationJob]: ...


@runtime_checkable
class ValidationResultRepository(Protocol):
    async def save(self, result: ValidationResult) -> None: ...
    async def get(self, result_id: str) -> ValidationResult | None: ...
    async def get_by_job(self, job_id: str) -> ValidationResult | None: ...


@runtime_checkable
class ExposureEventPublisher(Protocol):
    async def publish_result(
        self,
        job: ValidationJob,
        result: ValidationResult,
    ) -> None: ...
