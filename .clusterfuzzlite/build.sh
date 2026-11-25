#!/bin/bash -eu
# Build every Atheris harness in fuzz/ for ClusterFuzzLite (docs/testing.md).
#
# Runtime dependencies come from the hash-locked set the composite action installs. The
# package itself is not installed: it declares Python 3.12 and this image runs 3.11, so
# PyInstaller bundles the sources from src/ instead (they parse and import on 3.11).

pip3 install --require-hashes --no-deps -r .github/requirements/action.txt

for harness in fuzz/fuzz_*.py; do
  name=$(basename -s .py "$harness")
  compile_python_fuzzer "$harness" --paths src
  zip -qj "$OUT/${name}_seed_corpus.zip" "fuzz/corpus/$name"/*
  case "$name" in
    fuzz_quotes) dict=quotes ;;
    fuzz_probe_yaml) dict=yaml ;;
    *) dict=json ;;
  esac
  cp "fuzz/$dict.dict" "$OUT/$name.dict"
done
