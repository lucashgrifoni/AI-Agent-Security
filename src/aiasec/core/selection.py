"""Wording for a probe selection recorded in a report."""

from __future__ import annotations

from collections.abc import Mapping

LABELS = {"categories": "categories", "minSeverity": "min severity", "probeIds": "probe ids"}


def describe_selection(selection: Mapping[str, object]) -> str:
    """Describe the filters a run applied, as in `categories jailbreak; min severity high`."""

    parts = []
    for key, label in LABELS.items():
        value = selection.get(key)
        if value:
            text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
            parts.append(f"{label} {text}")
    return "; ".join(parts)
