"""Probe definition models and YAML loading helpers."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

PROBE_SCHEMA = "aiasec.probe/v1"
Severity = Literal["low", "medium", "high", "critical"]


class ProbeDocument(BaseModel):
    """Document-like input used by RAG or indirect prompt-injection probes."""

    model_config = ConfigDict(extra="forbid")

    path: str | None = None
    content: str | None = None
    injected: str | None = None


class ProbeInput(BaseModel):
    """Prompt, document, or tool-context input for a probe."""

    model_config = ConfigDict(extra="forbid")

    role: str
    content: str | None = None
    documents: list[ProbeDocument] = Field(default_factory=list)


class ProbeExpectation(BaseModel):
    """Expected security property checked by the rules evaluator."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    pattern: str | None = None
    tool_name: str | None = None
    on: str = "assistant_final_response"


class Probe(BaseModel):
    """Versioned adversarial probe definition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: Literal["aiasec.probe/v1"] = Field(alias="schema")
    id: str
    title: str
    category: str
    severity: Severity
    references: list[str] = Field(default_factory=list)
    inputs: list[ProbeInput]
    expectations: list[ProbeExpectation]
    # Only the rules evaluator exists. Accepting any other name would run the probe as
    # rules anyway and hide that the requested evaluator never ran.
    evaluator: Literal["rules"] = "rules"
    metadata: dict[str, str] = Field(default_factory=dict)

    _source: str | None = PrivateAttr(default=None)

    @property
    def source(self) -> str | None:
        """Return the machine-independent path of the YAML file this probe came from."""

        return self._source

    @field_validator("id", "title", "category")
    @classmethod
    def require_non_empty(cls, value: str) -> str:
        """Reject empty identity fields."""

        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @field_validator("expectations")
    @classmethod
    def require_expectations(cls, value: list[ProbeExpectation]) -> list[ProbeExpectation]:
        """A probe must assert at least one behavior."""

        if not value:
            raise ValueError("probe must define at least one expectation")
        return value


def load_probe_file(path: Path, *, root: Path | None = None) -> Probe:
    """Load and validate one probe YAML file."""

    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Probe file must contain a YAML mapping: {path}")
    probe = Probe.model_validate(data)
    probe._source = _source_path(path, root)
    return probe


def load_probes_from_dir(path: Path) -> list[Probe]:
    """Load all probe YAML files below a directory in stable order."""

    if not path.exists():
        raise FileNotFoundError(f"Probe directory does not exist: {path}")
    return [
        load_probe_file(probe_path, root=path) for probe_path in sorted(path.rglob("*.yaml"))
    ]


def _source_path(path: Path, root: Path | None) -> str:
    """Return a path that is safe to publish in a report.

    Reports are uploaded to code scanning, so an absolute path would leak the machine
    layout. Prefer the path relative to the working directory, which links to the file
    when the probes live in the scanned repository; otherwise anchor it at the probe root.
    """

    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        pass
    if root is not None:
        resolved_root = root.resolve()
        with suppress(ValueError):
            return (Path(resolved_root.name) / resolved.relative_to(resolved_root)).as_posix()
    return path.name
