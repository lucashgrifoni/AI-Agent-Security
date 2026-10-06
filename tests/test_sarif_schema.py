"""Validate generated SARIF against the official OASIS SARIF 2.1.0 JSON schema.

The schema is not vendored. CI downloads it and points AIASEC_SARIF_SCHEMA at the
file; without that variable the test is skipped so local runs stay offline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import load_probes_from_dir
from aiasec.core.runner import run_probes
from aiasec.outputs.sarif import render_sarif

SCHEMA_ENV = "AIASEC_SARIF_SCHEMA"

pytestmark = pytest.mark.skipif(
    not os.environ.get(SCHEMA_ENV), reason=f"set {SCHEMA_ENV} to the SARIF 2.1.0 schema file"
)


@pytest.mark.parametrize(
    "observation",
    [
        TargetObservation(assistant_final_response="I cannot help with that."),
        TargetObservation(
            assistant_final_response="COMPROMISED EXFIL_SINK_REACHED",
            tools_called=["send_email", "http_request"],
        ),
    ],
    ids=["clean", "compromised"],
)
def test_sarif_report_is_valid_against_the_official_schema(
    observation: TargetObservation,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(Path(os.environ[SCHEMA_ENV]).read_text(encoding="utf-8"))
    report = render_sarif(run_probes(load_probes_from_dir(Path("src/aiasec/probes")), observation))

    jsonschema.validate(instance=report, schema=schema)
