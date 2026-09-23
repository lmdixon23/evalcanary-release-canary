# ReplayDocket v0.2.0 External Release Canary

This repository is intentionally separate from `lmdixon23/evalcanary`.

It verifies the exact public action reference:

```yaml
uses: lmdixon23/EvalCanary@v0.2.0
```

against synthetic data on clean GitHub-hosted runners.

The canary requires:

- a successful tagged consumer run on Windows, Linux, and macOS;
- all seven declared Action outputs, including report paths and content-derived run ID;
- a deliberately failing policy that returns Action failure while preserving outputs;
- uploaded review packets;
- default report privacy (no original case content, verifier source, credential patterns,
  unexpected absolute paths, or a synthetic environment privacy marker);
- ReplayDocket v0.2.0 product identity with stable EvalCanary machine identifiers;
- the exact release tag remaining attached to the governed source commit.

This fixture contains no private benchmark or model data.

The negative control must have Action outcome `failure` and underlying exit code
`2`. Its `continue-on-error` step conclusion is `success` so the workflow can
inspect and upload outputs; that conclusion does not turn the blocked policy into
a passing comparison. Review the actual Action log to confirm exit code `2`.

Artifacts contain the three report files plus a separate output contract and a
clean-environment record. Absolute paths in the output contract are the declared
Action path outputs; the report files themselves must not contain absolute paths.
The fixed `SOURCE_DATE_EPOCH` controls synthetic report reproducibility, not the
release date. The existing workflow filename is retained to preserve its history.
