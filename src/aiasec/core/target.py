"""The one interface every live target implements, whatever carries the probes."""

from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self, runtime_checkable

from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import Probe


@runtime_checkable
class AgentTarget(Protocol):
    """An agent, harness or model that receives probes and reports what it did.

    Implementations start whatever they need when started, send each probe turn to the
    target, and return the final reply and the tool calls it reported. They never run a
    tool call (docs/adr/0002-never-execute-tool-calls.md).
    """

    @property
    def label(self) -> str:
        """How the target names itself in the run log."""
        ...

    def observe(self, probe: Probe) -> TargetObservation:
        """Send the probe's turns and return what the target replied and called."""
        ...

    def close(self) -> None:
        """Release the process or connection; safe to call twice."""
        ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
