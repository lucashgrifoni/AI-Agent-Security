"""docs/releasing.md moves "the Unreleased section" under the version; there must be one."""

from __future__ import annotations

import re
from pathlib import Path


def test_the_changelog_has_at_most_one_unreleased_section_and_it_comes_first() -> None:
    headings = re.findall(r"(?m)^## (.+)$", Path("CHANGELOG.md").read_text(encoding="utf-8"))

    assert headings.count("Unreleased") <= 1
    assert "Unreleased" not in headings[1:]
