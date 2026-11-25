# aiasec container image.
#
# Two stages. The build stage installs the hash-locked build tools and builds the wheel
# from the source tree. The final stage starts again from the same base, installs the
# hash-locked runtime dependency set and the wheel (with --no-deps, from the local file
# only), removes pip, and runs as a non-root user. No build tool, compiler, source tree
# or package cache reaches the image that ships.
#
# The base image is pinned by digest (python:3.12-slim, multi-arch index); Dependabot's
# docker entry proposes digest updates. Build it from the repository root:
#
#   docker build -t aiasec .
#   docker run --rm aiasec --version

FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b AS build

# Build timestamps follow the commit when the caller passes its time; 0 otherwise.
ARG SOURCE_DATE_EPOCH=0
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY .github/requirements/build.txt /tmp/build.txt
RUN python -m pip install --require-hashes -r /tmp/build.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --no-isolation --outdir /dist

FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aiasec" \
      org.opencontainers.image.description="Rules-only security regression testbed for AI agents and MCP tool boundaries." \
      org.opencontainers.image.source="https://github.com/lucashgrifoni/AI-Agent-Security" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY .github/requirements/runtime.txt /tmp/runtime.txt
COPY --from=build /dist/ /tmp/dist/
RUN python -m pip install --require-hashes -r /tmp/runtime.txt \
    && python -m pip install --no-deps --no-index /tmp/dist/*.whl \
    && python -m pip uninstall --yes pip \
    && rm -rf /tmp/runtime.txt /tmp/dist \
    && useradd --uid 10001 --user-group --create-home --home-dir /home/aiasec \
        --shell /usr/sbin/nologin aiasec \
    && install -d -o 10001 -g 10001 /work

# Mount the directory with target configs and reports here: docker run -v "$PWD:/work".
WORKDIR /work
USER 10001:10001
# A command-line tool that runs and exits: there is no long-running service to probe.
HEALTHCHECK NONE
ENTRYPOINT ["aiasec"]
CMD ["--help"]
