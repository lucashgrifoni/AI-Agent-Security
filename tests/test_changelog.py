"""The changelog always opens with one Unreleased section.

docs/releasing.md renames it to the new version and opens a new, empty one, so the
next change always has exactly one place to go.
"""

from __future__ import annotations

import re
from pathlib import Path


def test_the_changelog_opens_with_exactly_one_unreleased_section() -> None:
    headings = re.findall(r"(?m)^## (.+)$", Path("CHANGELOG.md").read_text(encoding="utf-8"))

    assert headings[:1] == ["Unreleased"]
    assert headings.count("Unreleased") == 1
