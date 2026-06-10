"""Filesystem artifact workspace used by the local workflow harness."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypeVar

from riskos.schemas.artifacts import Artifact

ArtifactT = TypeVar("ArtifactT", bound=Artifact)
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class WorkspaceError(Exception):
    pass


class ArtifactWorkspace:
    """Persist immutable, versioned artifacts under one assessment root."""

    def __init__(self, root: str | Path, assessment_id: str):
        self.root = Path(root)
        self.assessment_id = _safe_segment("assessment_id", assessment_id)

    def write(self, artifact: Artifact) -> Path:
        if artifact.assessment_id != self.assessment_id:
            raise WorkspaceError(
                f"artifact assessment {artifact.assessment_id!r} does not match "
                f"workspace assessment {self.assessment_id!r}"
            )

        path = self._path(artifact.artifact_type, artifact.artifact_id, artifact.version)
        if path.exists():
            raise WorkspaceError(f"artifact version already exists: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            artifact.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return path

    def read(
        self,
        artifact_type: str,
        artifact_id: str,
        model: type[ArtifactT],
        version: int | None = None,
    ) -> ArtifactT:
        if version is None:
            version = self._latest_version(artifact_type, artifact_id)
            if version is None:
                raise WorkspaceError(
                    f"artifact not found: {artifact_type}/{artifact_id}"
                )

        path = self._path(artifact_type, artifact_id, version)
        if not path.exists():
            raise WorkspaceError(f"artifact version not found: {path}")
        return model.model_validate_json(path.read_text(encoding="utf-8"))

    def _latest_version(self, artifact_type: str, artifact_id: str) -> int | None:
        artifact_type = _safe_segment("artifact_type", artifact_type)
        artifact_id = _safe_segment("artifact_id", artifact_id)
        directory = self.root / self.assessment_id / "artifacts" / artifact_type / artifact_id
        latest = None
        for path in directory.glob("v*.json"):
            try:
                version = int(path.stem.removeprefix("v"))
            except ValueError:
                continue
            if latest is None or version > latest:
                latest = version
        return latest

    def _path(self, artifact_type: str, artifact_id: str, version: int) -> Path:
        artifact_type = _safe_segment("artifact_type", artifact_type)
        artifact_id = _safe_segment("artifact_id", artifact_id)
        if version < 1:
            raise WorkspaceError("artifact version must be positive")
        return (
            self.root
            / self.assessment_id
            / "artifacts"
            / artifact_type
            / artifact_id
            / f"v{version}.json"
        )


def _safe_segment(label: str, value: str) -> str:
    if not value or not _SAFE_SEGMENT.fullmatch(value):
        raise WorkspaceError(f"invalid {label}: {value!r}")
    return value
