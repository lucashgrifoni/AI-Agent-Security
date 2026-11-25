# Testing aiasec

aiasec is tested in three layers. Each answers a different question, and none of them
stands in for another.

| Layer | Question it answers | Where | When it runs |
| --- | --- | --- | --- |
| Unit and property tests (pytest, Hypothesis) | Does the code do what the tests say? | `tests/` | Every push and pull request (`ci.yml`), on Linux, Windows and macOS, with a 90% line and branch coverage floor |
| Coverage-guided fuzzing (Atheris, ClusterFuzzLite) | Does a parser of untrusted text fail only in the ways it documents? | `fuzz/`, `.clusterfuzzlite/` | Ten minutes on every pull request (`cflite-pr.yml`), thirty minutes daily (`cflite-batch.yml`), and the seed corpus on every test run |
| Sampled mutation testing (mutmut) | Would the tests notice if the gate or the rules evaluator were wrong? | `[tool.mutmut]` in `pyproject.toml` | Weekly and on demand (`mutation.yml`); informational |

## Fuzzing

### What is fuzzed

aiasec reads text written by the agent under test, by an MCP server, by an LLM judge, by
probe authors and by whatever produced a SARIF report. Each harness in `fuzz/` feeds one
of those readers bytes from libFuzzer through Atheris and lets every exception the
reader does not document crash the run. Where a property must hold for any input, the
harness checks it too (the oracle column).

| Harness | Reads | Expected errors | Oracle |
| --- | --- | --- | --- |
| `fuzz_quotes.py` | A reply, through the quote stripping behind `ignore_quoted` (`rules._without_quotes`) | none | the result is never longer than the reply |
| `fuzz_judge_reply.py` | An LLM judge's answer (`judge._parse`) | none | the verdict is `yes`, `no` or `unclear`; the reason fits the report |
| `fuzz_probe_yaml.py` | A probe file (`probe.parse_probe`) | `ValueError` (pydantic's `ValidationError` and `UnicodeDecodeError` included), `yaml.YAMLError` | a probe that loads has an id, inputs and expectations |
| `fuzz_sarif_report.py` | A report, as `aiasec gate` and `aiasec compare` read it (`gate.parse_sarif`, `count_executed_probes`, `read_selections`, `count_severities`, `compare.summarize`) | `ValueError` | every result is counted once; a run compared with itself shows no difference |
| `fuzz_tool_calls.py` | The tool calls a target reports (`conversation.parse_tool_calls`), then every argument value an argument check reads | `ValueError` | no call is lost or keeps a blank name; the observation counts every called tool |
| `fuzz_mcp_tools.py` | A `tools/list` result (`audit.audit_tools`, `tooldefs.make_snapshot`, `compare_snapshots`) | `ValueError` from `make_snapshot` | what the audit prints has no hidden character left; a snapshot is stable and UNCHANGED against itself |

Each harness has a seed corpus in `fuzz/corpus/<harness>/` (bundled probes, reports
aiasec wrote, the MCP fixtures, and the inputs behind past crashes) and uses one of the
libFuzzer dictionaries `fuzz/json.dict`, `fuzz/quotes.dict` or `fuzz/yaml.dict`.

Writing the harnesses found three crashes, now fixed, each with a regression test and a seed:
a deeply nested report escaped `aiasec gate` and `aiasec compare` as `RecursionError`
(exit code 1 and a traceback instead of 2), so did a deeply nested probe file, and a
tool definition nested over a thousand levels deep crashed `aiasec mcp audit`.

### How it runs

`.clusterfuzzlite/Dockerfile` builds on the OSS-Fuzz Python builder image (pinned by
digest), which ships Atheris, libFuzzer and PyInstaller. `build.sh` installs the runtime
dependencies from the hash-locked `.github/requirements/action.txt` and bundles every
`fuzz/fuzz_*.py` with its seed corpus and dictionary.

- `cflite-pr.yml` fuzzes all harnesses for 600 seconds in total on each pull request.
- `cflite-batch.yml` fuzzes them for 1,800 seconds a day and keeps the grown corpus as
  an artifact the pull-request runs start from.
- `tests/test_fuzz_harnesses.py` replays every seed through every harness on every
  platform, without Atheris. It also replaces each fuzzed function with one that raises
  an undocumented exception and requires the harness to let it through, which proves
  that some seed reaches the function and that the harness does not swallow crashes.

Both workflows build with AddressSanitizer. For pure Python code the findings are
uncaught exceptions, failed oracles, timeouts (a regular expression that backtracks)
and memory blow-ups; the sanitizer watches the native code underneath (the interpreter,
pydantic-core).

### Running it locally

On any platform, replay the seeds:

```bash
python -m pytest tests/test_fuzz_harnesses.py
```

Atheris builds on Linux only. With Docker (Linux, macOS or Windows), build and run the
same image ClusterFuzzLite uses:

```bash
docker build -t aiasec-cflite -f .clusterfuzzlite/Dockerfile .
docker volume create aiasec-fuzz-out
docker run --rm -v aiasec-fuzz-out:/out \
  -e SANITIZER=address -e FUZZING_ENGINE=libfuzzer -e FUZZING_LANGUAGE=python \
  -e ARCHITECTURE=x86_64 aiasec-cflite compile
docker run --rm -v aiasec-fuzz-out:/out aiasec-cflite bash -c '
  mkdir -p /tmp/corpus && cd /tmp/corpus && unzip -q /out/fuzz_quotes_seed_corpus.zip
  cd /out && ./fuzz_quotes -dict=fuzz_quotes.dict -max_total_time=60 -timeout=25 /tmp/corpus'
```

Replace `fuzz_quotes` with any harness name. On Git Bash for Windows, prefix the
`docker run` commands with `MSYS_NO_PATHCONV=1`.

### Reading the results

- **A crash** fails the workflow, and ClusterFuzzLite uploads the input that caused it
  as an artifact. Run the harness on that file (`./fuzz_quotes crash-<hash>` in the
  container above, or `test_one_input` on its bytes in a Python shell) to get the
  Python traceback. If the exception is one the reader should document, fix the reader
  so it raises it; if a different exception is right, document it and teach the
  harness. Either way, add the input to the harness's seed corpus and a unit test that
  fails before the fix.
- **A timeout** usually points at a regular expression that backtracks on a crafted
  input; time the reader on the reproducer before changing the pattern.
- **A failed oracle** (`AssertionError` raised by the harness) means a reader returned
  a wrong answer without crashing. Those are the findings that matter most here.
- **No crash** is not a proof of safety. It is bounded by the coverage the harness
  reached, the time it ran and the inputs it could build. Atheris measures the Python
  code of aiasec only: the regular expression engine runs in C, so `fuzz_quotes` reports
  little coverage although every pattern is exercised.

### Known limits

- The OSS-Fuzz builder runs Python 3.11; aiasec declares 3.12 and later. The sources
  parse and import on 3.11, and build.sh bundles them from `src/` instead of installing
  the package. A defect that only Python 3.12 shows will not be found here.
- `fuzz_tool_calls.py` and `fuzz_mcp_tools.py` decode JSON as their callers do (their
  callers turn the decoder's `ValueError` and `RecursionError` into an error), so the
  decoding itself is the standard library's, not aiasec's.
- Python's JSON decoder accepts `NaN` and `Infinity`. `NaN` never equals itself, so a
  tool definition carrying it is reported as changed by `aiasec mcp tools diff` against an
  identical snapshot: a false alarm, never a missed change. `fuzz_mcp_tools.py` leaves
  these constants out so its oracle keeps finding new defects; the false alarm is open.

## Mutation testing

### What is mutated

mutmut changes the code of the two modules a release verdict rests on, one small edit
at a time (a `>` becomes `>=`, a `True` becomes `False`, a string or a return value is
replaced), and runs the tests that reach the edited function against each mutant:

- `src/aiasec/core/evaluator/rules.py` decides whether a probe passed;
- `src/aiasec/core/gate.py` reads the report and decides the release gate.

These modules are a sample of the code base, chosen because a defect in them can pass
a release that should fail. Mutating the whole package would multiply the cost without
changing the decisions this report supports.

### Running it

mutmut forks for every mutant and runs on Linux and macOS, not on native Windows. The
weekly workflow `mutation.yml` (also started by hand from the Actions tab) uploads a
`mutation-report` artifact with the score and every surviving mutant.

Locally, on Linux, macOS or WSL, with the dev dependencies installed
(`pip install -e ".[dev]"`):

```bash
mutmut run            # mutates the two modules set in [tool.mutmut]
mutmut results        # lists the mutants that survived
mutmut show <mutant>  # the diff of one mutant
mutmut browse         # an interactive view of all of them
```

On Windows, run the same commands in the `python:3.12` Docker image with the repository
mounted, after `pip install --require-hashes -r .github/requirements/ci.txt` and
`pip install --no-deps --no-build-isolation -e .`.

### Reading the results

The score is the share of mutants the tests detected: (killed + timeout) / (total -
skipped). It is informational. It does not gate a merge or a release, because a
threshold set before the surviving mutants are understood would reward deleting them
rather than testing better.

What matters is each surviving mutant. It is one of four things:

- **A missing assertion**: a test runs the edited line but checks nothing that changes.
  Add the assertion.
- **A missing case**: no test drives that path. Add the case.
- **Untested by choice**: logging, or a message wording nobody wants to pin. Leave it,
  and say so where the survivor is discussed.
- **An equivalent mutant**: the edit cannot change behavior (for example, a bound that
  the input can never reach), so no test can detect it. Record the argument.

Never exclude a survivor to raise the score. Line coverage says the code ran; the
mutation score says whether a wrong result would have been noticed. The gap between the
two is the finding.
