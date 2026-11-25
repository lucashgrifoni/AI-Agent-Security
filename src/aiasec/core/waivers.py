"""Gate waivers: a known failure the team accepted, with a reason, an owner and an end.

Without waivers, one accepted failure forces a looser threshold for every probe of its
severity. A waiver removes only the results it names (a probe, or one expectation of a
probe) from the gate's counts, and only until it expires. An expired waiver does not
apply and is reported, so the failure comes back instead of staying hidden.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

# A waiver must end: one that runs longer than this is refused.
MAX_WAIVER_DAYS = 366


class Waiver(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    probe_id: str = Field(alias="probeId", min_length=1)
    # Leave out to waive every expectation of the probe.
    expectation_id: str | None = Field(default=None, alias="expectationId", min_length=1)
    reason: str = Field(min_length=10)
    owner: str = Field(min_length=1)
    expires: date

    def matches(self, result: dict[str, Any]) -> bool:
        if result.get("ruleId") != self.probe_id:
            return False
        if self.expectation_id is None:
            return True
        properties = result.get("properties")
        return isinstance(properties, dict) and (
            properties.get("expectationId") == self.expectation_id
        )

    def summary(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True, mode="json")


class WaiverFile(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: Literal["aiasec.waivers/v1"] = Field(alias="schema")
    waivers: list[Waiver]


def load_waivers(path: Path, *, today: date) -> list[Waiver]:
    """Read a waiver file. A waiver that runs past MAX_WAIVER_DAYS raises ValueError."""

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    waivers = WaiverFile.model_validate(data).waivers
    horizon = today + timedelta(days=MAX_WAIVER_DAYS)
    for waiver in waivers:
        if waiver.expires > horizon:
            raise ValueError(
                f"the waiver of {waiver.probe_id} expires on {waiver.expires}, more than "
                f"{MAX_WAIVER_DAYS} days away; give it an end the team will review"
            )
    return waivers


def split_waived(
    results: Iterable[dict[str, Any]], waivers: list[Waiver], *, today: date
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Results still counted, waivers that removed a result, and expired waivers."""

    active = [waiver for waiver in waivers if waiver.expires >= today]
    expired = [waiver.summary() for waiver in waivers if waiver.expires < today]
    kept: list[dict[str, Any]] = []
    used: dict[Waiver, int] = {}
    for result in results:
        waiver = next((waiver for waiver in active if waiver.matches(result)), None)
        if waiver is None:
            kept.append(result)
        else:
            used[waiver] = used.get(waiver, 0) + 1
    waived = [{**waiver.summary(), "results": count} for waiver, count in used.items()]
    return kept, waived, expired
