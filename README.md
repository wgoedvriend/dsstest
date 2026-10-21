# DSS 6.5: external SD-JWT payload proof of concept

This experiment answers one architectural question:

> Can another service assemble an unsigned SD-JWT attestation payload as JSON, after which a Java seal service wraps it in a DSSDocument and calls SDJWTService.getDataToSign(DSSDocument, JAdESSignatureParameters)?

## Test flow

1. Load the external file `src/test/resources/external-payload.json`. In production its bytes would arrive over HTTP.
2. Wrap bytes in `new InMemoryDocument(json, "external-payload.json")`.
3. Call `SDJWTService.getDataToSign(document, params)`.
4. Sign the returned ToBeSigned bytes with a **throwaway** self-signed RSA test certificate.
5. Call `SDJWTService.signAttestation(document, params, signature)`.
6. Verify the resulting compact JWS signature using the public key.

This fixture is a plain claimset, not a complete selectively disclosable SD-JWT. It does **not** test externally supplied _sd hashes, disclosures, issuer trust, wallet interoperability, validity of claims, or a qualified electronic seal.

## Run

Open the **Actions** tab and inspect the **Verify DSS 6.5 external payload** workflow. GitHub Actions generates a temporary PKCS#12 keystore (never committed) and runs `mvn clean test`.

For local runs, install JDK 21 and Maven, then generate the test key:

```bash
keytool -genkeypair -alias test-seal -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -dname "CN=DSS Test Seal,O=Example,C=NL" -validity 2 -storetype PKCS12 -keystore src/test/resources/test-only.p12 -storepass changeit -keypass changeit -noprompt
mvn clean test
```

## Status

**Not yet verified green.** The exact DSS 6.5 methods are documented in the official API, but a passing GitHub Actions execution must confirm the integration.

- [SDJWTService 6.5 JavaDoc](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/eu/europa/esig/dss/attestation/sd/jwt/creation/SDJWTService.html)
- [DSS upstream](https://github.com/esig/dss)

Never reuse the example key or password in production. No production signing key belongs in this repository.
