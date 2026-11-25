# ClusterFuzzLite build image for the Atheris harnesses in fuzz/ (docs/testing.md).
#
# The OSS-Fuzz Python builder ships Atheris, libFuzzer and PyInstaller. It is pinned by
# digest (the v1 image published on 2026-11-25); Dependabot moves the digest with v1.
# Its Python is 3.11, one minor version below what aiasec supports, so build.sh puts
# the sources on the path instead of installing the package.
FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:5a20f6927f4157bafbb9f66eb62a99dd9e6e92ed94b10ffaee4262b9bedac08a

COPY . $SRC/aiasec
WORKDIR $SRC/aiasec
COPY .clusterfuzzlite/build.sh $SRC/
