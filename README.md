# EvalCanary v0.1.1 External Release Canary

This repository is intentionally separate from `lmdixon23/evalcanary`.

It verifies the exact public action reference:

```yaml
uses: lmdixon23/evalcanary@v0.1.1
```

against synthetic data on clean GitHub-hosted runners.

The canary requires:

- a successful tagged consumer run on Windows, Linux, and macOS;
- correct Action outputs;
- a deliberately failing policy that returns Action failure while preserving outputs;
- uploaded review packets;
- default report privacy (no original case content or verifier source);
- the exact release tag remaining attached to the governed source commit.

This fixture contains no private benchmark or model data.
