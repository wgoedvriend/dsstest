# DSS 6.5 – VC payload → DSS elektronische zegelservice

This repository demonstrates **three separately containerized Java services** with Docker Compose.

1. **vc-service**: a mock Verifiable Credential payload provider that produces an unsigned JSON claimset, without using DSS.
2. **orchestrator**: an application that requests the JSON payload and forwards it **unchanged** to the signing service. It provides a step-by-step browser interface.
3. **dss-service**: receives that JSON and invokes the official `SDJWTService.getDataToSign(DSSDocument, JAdESSignatureParameters)` overload. The service signs with a disposable self-signed RSA key and builds the signed attestation.

## Follow the flow locally

Install Docker Desktop with Compose. From the repository root:

```bash
docker compose up --build
```

Then open **http://localhost:8080**. Click **Voer ketentest uit** to see each request, the unsigned JSON, DSS signing outcome, and resulting compact token. No real VC provider or external network service is needed.

Alternatively:

```bash
curl -X POST http://localhost:8080/run
docker compose logs -f vc-service dss-service orchestrator
docker compose down
```

The services are isolated within the Compose backend network. Only the orchestrator is mapped to localhost. See [Architecture and sequence diagram](docs/ARCHITECTURE.md).

## Automated verification

- [GitHub Actions – Container end-to-end](../../actions/workflows/container.yml): builds all containers, invokes the orchestrator and checks for `ok=true`.
- [GitHub Actions – Unit/integration tests](../../actions/workflows/verify.yml): builds Maven tests using a fresh test certificate.

**Status: committed, but no successful CI run has yet been independently verified.** If CI is red, inspect build logs before treating the prototype as proven.

## What this proves (and what it does not)

This project is designed to demonstrate external JSON → `InMemoryDocument` → `getDataToSign` → signature → `signAttestation` → signature verification.

The mock VC service is **not** a production VC issuer; the sample has no `_sd` disclosures. It does **not** establish SD-JWT-VC profile compatibility, qualified eIDAS sealing, certificate trust, holder binding, or compliance with a real VC service protocol. In particular, a plain signed JWT should not be marketed as a full selectively disclosable Verifiable Credential.

For future extension replace only the mock VC service with an authenticated actual VC API, specify its payload contract (including externally generated disclosures) and add domain-specific validation before sealing.

See the [official DSS 6.5 SDJWTService API](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/eu/europa/esig/dss/attestation/sd/jwt/creation/SDJWTService.html).

**Security**: the disposable PKCS#12 key inside the Docker image and hardcoded demo password are strictly for local experiments. Do not reuse for production. Keep production private keys in a hardware-backed signing solution or trusted remote signer.
