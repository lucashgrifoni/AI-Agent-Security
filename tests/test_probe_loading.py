from pathlib import Path

import pytest

from aiasec.core.probe import load_probe_file, load_probes_from_dir, parse_probe


def test_load_probe_file_accepts_bundled_probe() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )

    assert probe.id == "direct-injection-001"
    assert probe.expectations[0].kind == "regex_not_match"


def test_load_probes_from_dir_loads_every_bundled_yaml_file() -> None:
    root = Path("src/aiasec/probes")

    probes = load_probes_from_dir(root)

    assert len(probes) == len(list(root.rglob("*.yaml")))
    assert {"direct-injection-001", "tool-coercion-001"} <= {probe.id for probe in probes}



def test_parse_probe_reads_the_same_probe_as_the_file_loader() -> None:
    path = Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")

    parsed = parse_probe(path.read_text(encoding="utf-8"))

    assert parsed.model_dump() == load_probe_file(path).model_dump()
    assert parsed.source is None


def test_a_probe_file_nested_too_deeply_is_invalid_instead_of_a_crash(tmp_path: Path) -> None:
    # Found by fuzz/fuzz_probe_yaml.py: the YAML composer recurses once per level and
    # raised RecursionError, which none of the probe loaders' callers expect.
    path = tmp_path / "deep.yaml"
    path.write_text("[" * 5_000 + "]" * 5_000, encoding="utf-8")

    with pytest.raises(ValueError, match="nests too deeply"):
        load_probe_file(path)
