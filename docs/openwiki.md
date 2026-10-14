# Repository wiki with OpenWiki

Start at the [repository wiki](../openwiki/quickstart.md) to find explanations linked to source. Existing user guides remain the full reference.

## Local integration

OpenWiki 0.7.2 requires Node.js 22.22.0 or newer. From this Git repository, install the pinned CLI and the project integration:

~~~sh
npm install --global openwiki@0.7.2
openwiki integrations install codex --project .
~~~

Restart Codex in the repository, then request an update of the existing wiki. Other hosts are described in the [upstream quick start](https://github.com/langchain-ai/openwiki#quick-start). The repository brief is in [INSTRUCTIONS.md](../openwiki/INSTRUCTIONS.md); the source exclusions are in [.openwikiignore](../.openwikiignore).

## Maintenance and limits

OpenWiki maintains claims, source fingerprints, indexes and completion metadata through its native lifecycle. Review consequential statements against current source and update the affected pages after source changes. Verification metadata records documentation checks; it does not certify application security or compliance. Search and read relevant sections to check retrieval.

Project-local integration files remain local. The generated scheduled workflow is excluded from this documentation change; no scheduled generation job is activated. Private repository documentation stays private. Follow the repository contribution and validation instructions before proposing an update.
