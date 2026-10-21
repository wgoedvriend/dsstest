# DSS SD-JWT external payload proof of concept

Proof of concept for DSS 6.5: an externally supplied JSON attestation payload is wrapped in `InMemoryDocument`, passed to `SDJWTService.getDataToSign`, signed, and supplied to `signAttestation`.

See the integration test and GitHub Actions CI. This repository uses test-only self-signed keys, not production seals.
