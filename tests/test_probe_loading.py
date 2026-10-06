from pathlib import Path

from aiasec.core.probe import load_probe_file, load_probes_from_dir


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

