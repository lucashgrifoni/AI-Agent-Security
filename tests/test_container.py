"""The container image: what the Dockerfile builds, and how the workflows build and push it.

No test here runs Docker. They read the Dockerfile, .dockerignore and the workflow YAML,
so a change that drops the digest pin, the non-root user, the hash-locked install or the
least-privilege publish job fails the suite on every platform.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

DOCKERFILE = Path("Dockerfile")
RUNTIME_LOCK = ".github/requirements/runtime.txt"
IMAGE = "ghcr.io/lucashgrifoni/ai-agent-security-testbed"


def _instructions(path: Path = DOCKERFILE) -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) pairs, with continuation lines joined and comments dropped."""

    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keyword, _, arguments = line.partition(" ")
            pairs.append((keyword.upper(), arguments.strip()))
    return pairs


def _final_stage() -> list[tuple[str, str]]:
    instructions = _instructions()
    last_from = max(i for i, (keyword, _) in enumerate(instructions) if keyword == "FROM")
    return instructions[last_from:]


def _workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load(Path(f".github/workflows/{name}").read_text(encoding="utf-8"))


def _steps_using(job: dict[str, Any], action: str) -> list[dict[str, Any]]:
    return [step for step in job["steps"] if str(step.get("uses", "")).startswith(action)]


def test_every_base_image_is_pinned_by_digest() -> None:
    bases = [arguments for keyword, arguments in _instructions() if keyword == "FROM"]

    assert len(bases) == 2
    for base in bases:
        image = base.split()[0]
        assert re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", image), base


def test_the_final_stage_runs_as_a_non_root_user() -> None:
    users = [arguments for keyword, arguments in _final_stage() if keyword == "USER"]

    assert users, "the final stage sets no USER, so the image runs as root"
    assert users[-1].split(":")[0] not in {"root", "0"}


def test_the_entrypoint_is_aiasec() -> None:
    entrypoints = [arguments for keyword, arguments in _final_stage() if keyword == "ENTRYPOINT"]

    assert [json.loads(entrypoint) for entrypoint in entrypoints] == [["aiasec"]]


def test_the_final_stage_installs_the_locked_runtime_set_and_the_wheel_only() -> None:
    runs = " ".join(arguments for keyword, arguments in _final_stage() if keyword == "RUN")
    installs = [part for part in runs.split("&&") if "pip install" in part]

    locked = [part for part in installs if RUNTIME_LOCK.split("/")[-1] in part]
    wheel = [part for part in installs if ".whl" in part]
    assert len(installs) == 2 and len(locked) == 1 and len(wheel) == 1, installs
    assert "--require-hashes" in locked[0]
    assert "--no-deps" in wheel[0] and "--no-index" in wheel[0]
    # No build tools in the image that ships: the build stage keeps them.
    assert "build.txt" not in runs and "pip uninstall" in runs
    copies = " ".join(arguments for keyword, arguments in _final_stage() if keyword == "COPY")
    assert "src" not in copies.split()


def test_the_image_carries_oci_source_and_license_labels() -> None:
    labels = " ".join(arguments for keyword, arguments in _final_stage() if keyword == "LABEL")
    license_text = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"][
        "license"
    ]["text"]

    source = "https://github.com/lucashgrifoni/AI-Agent-Security"
    assert f'org.opencontainers.image.source="{source}"' in labels
    assert f'org.opencontainers.image.licenses="{license_text}"' in labels


def test_the_build_context_leaves_out_git_and_keeps_what_the_build_needs() -> None:
    patterns = [
        line.strip()
        for line in Path(".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    def ignored(path: str) -> bool:
        result = False
        for pattern in patterns:
            negated = pattern.startswith("!")
            if fnmatch.fnmatch(path, pattern.removeprefix("!")):
                result = not negated
        return result

    assert ignored(".git") and ignored(".env")
    copied = [
        arguments.split()[0]
        for keyword, arguments in _instructions()
        if keyword == "COPY" and "--from" not in arguments
    ]
    for source in copied:
        assert not ignored(source), source
        assert Path(source).exists(), source


def test_pull_requests_build_and_smoke_run_the_image_without_pushing() -> None:
    workflow = _workflow("ci.yml")
    job = workflow["jobs"]["container"]
    script = "\n".join(step.get("run", "") for step in job["steps"])

    assert "pull_request" in workflow[True]
    assert job["permissions"] == {"contents": "read"}
    assert "docker build" in script and "docker push" not in script
    assert "--version" in script and "probes list" in script


def test_the_container_job_allowlist_covers_the_docker_hub_hosts() -> None:
    # Docker Hub serves the base image layers from its Cloudflare CDN and its R2 blob
    # store; under egress-policy block, a missing host fails every pull request.
    job = _workflow("ci.yml")["jobs"]["container"]
    harden = _steps_using(job, "step-security/harden-runner@")[0]["with"]
    allowed = set(harden["allowed-endpoints"].split())

    assert harden["egress-policy"] == "block"
    assert {
        "auth.docker.io:443",
        "registry-1.docker.io:443",
        "production.cloudflare.docker.com:443",
        "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com:443",
    } <= allowed


def _jobs_granting(permission: str) -> list[tuple[str, str]]:
    return [
        (name, job_name)
        for name in sorted(path.name for path in Path(".github/workflows").glob("*.yml"))
        for job_name, job in _workflow(name)["jobs"].items()
        if (job.get("permissions") or {}).get(permission) == "write"
    ]


def test_no_third_party_action_runs_where_packages_can_be_written() -> None:
    # Harden-Runner is the one exception the repository requires on every Linux job.
    for name, job_name in _jobs_granting("packages"):
        for step in _workflow(name)["jobs"][job_name]["steps"]:
            action = str(step.get("uses", "actions/"))
            assert action.startswith(("actions/", "step-security/harden-runner@")), (
                f"{name}:{job_name} runs {action} next to packages: write"
            )


def test_the_image_sbom_is_generated_in_a_job_that_holds_no_credential() -> None:
    jobs = _workflow("publish.yml")["jobs"]
    job = jobs["container-build"]
    sbom = _steps_using(job, "anchore/sbom-action@")

    assert job["permissions"] == {"contents": "read"}
    assert len(sbom) == 1
    assert sbom[0]["with"]["github-token"] == ""
    assert sbom[0]["with"]["upload-artifact"] is False
    assert sbom[0]["with"]["upload-release-assets"] is False
    # The image archive is uploaded before the scanner runs, and the push job checks
    # that the archive holds the image ID recorded right after the build.
    steps = job["steps"]
    paths = [(step.get("with") or {}).get("path") for step in steps]
    assert paths.index("aiasec-image.tar") < steps.index(sbom[0])
    assert "image-id" in job["outputs"]
    push = jobs["container"]
    assert push["needs"] == "container-build"
    script = "\n".join(step.get("run", "") for step in push["steps"])
    assert "docker load" in script and '"$IMAGE_ID"' in script and "docker build" not in script


def test_only_the_release_job_can_push_the_image_and_it_attests_it() -> None:
    assert _jobs_granting("packages") == [("publish.yml", "container")]

    jobs = _workflow("publish.yml")["jobs"]
    job = jobs["container"]
    script = "\n".join(step.get("run", "") for step in job["steps"])
    assert job["env"]["IMAGE"] == IMAGE
    assert 'docker push "$IMAGE:$VERSION"' in script
    # A rerun must not replace an image tag that users may already have pulled and verified.
    assert 'docker manifest inspect "$IMAGE:$VERSION"' in script
    provenance = _steps_using(job, "actions/attest-build-provenance@")
    sbom = _steps_using(jobs["container-build"], "anchore/sbom-action@")
    sbom_attestation = _steps_using(job, "actions/attest@")
    assert len(provenance) == len(sbom) == len(sbom_attestation) == 1
    assert sbom[0]["with"]["format"] == "cyclonedx-json"
    assert Path(sbom_attestation[0]["with"]["sbom-path"]).name == sbom[0]["with"]["output-file"]
    for attestation in (*provenance, *sbom_attestation):
        assert attestation["with"]["subject-name"] == IMAGE
        assert attestation["with"]["push-to-registry"] is True


def test_latest_moves_only_for_the_highest_full_release_after_attestation() -> None:
    steps = _workflow("publish.yml")["jobs"]["container"]["steps"]
    latest = [i for i, step in enumerate(steps) if "$IMAGE:latest" in step.get("run", "")]
    attested = [
        i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/attest")
    ]

    assert len(latest) == 1, "exactly one step may move :latest"
    step = steps[latest[0]]
    # release: published also fires for pre-releases.
    assert step["if"].replace(" ", "") == "${{!github.event.release.prerelease}}"
    # A patch to an older line must not move :latest back.
    assert "--exclude-pre-releases" in step["run"] and "sort -V" in step["run"]
    assert latest[0] > max(attested)


def _bash_blocks(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    return "\n".join(re.findall(r"```bash\n(.*?)```", text, re.S))


def test_the_documented_image_commands_verify_and_run_one_digest() -> None:
    # Verifying a tag and then running the same tag resolves it twice: the image that
    # runs may not be the one that was verified.
    for doc in ("README.md", "docs/releasing.md"):
        commands = _bash_blocks(doc)
        tagged = [line for line in commands.splitlines() if f"{IMAGE}:" in line]

        assert tagged and all("imagetools inspect" in line for line in tagged), (doc, tagged)
        assert f'image="{IMAGE}@$digest"' in commands, doc
        assert 'gh attestation verify "oci://$image"' in commands, doc
    assert 'docker run --rm "$image"' in _bash_blocks("README.md")


def test_the_security_workflow_scope_note_matches_the_shipped_image() -> None:
    header = Path(".github/workflows/security.yml").read_text(encoding="utf-8").split("\nname:")[0]

    assert DOCKERFILE.exists()
    assert "Dockerfile, or Kubernetes manifests here" not in header
    # The image is not vulnerability-scanned in CI: the gap is recorded and owned.
    assert "docs/releasing.md" in header
    assert "## Known gaps" in Path("docs/releasing.md").read_text(encoding="utf-8")
