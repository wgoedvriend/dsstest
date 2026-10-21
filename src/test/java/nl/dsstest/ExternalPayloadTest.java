package nl.dsstest;

import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class ExternalPayloadTest {
    @Test
    void externalPayloadCanBeSignedWithDss() throws Exception {
        byte[] json;
        try (InputStream input = getClass().getResourceAsStream("/external-payload.json")) {
            assertNotNull(input);
            json = input.readAllBytes();
        }

        // Source is an external artifact. No SDJWTPayloadParameters is used.
        DSSDocument payload = new InMemoryDocument(json, "external-payload.json");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] password = "changeit".toCharArray();
        try (InputStream input = getClass().getResourceAsStream("/test-only.p12")) {
            assertNotNull(input, "Generate test-only.p12 in CI using keytool");
            ks.load(input, password);
        }
        PrivateKey key = (PrivateKey) ks.getKey("test-seal", password);
        X509Certificate cert = (X509Certificate) ks.getCertificate("test-seal");

        JAdESSignatureParameters params = new JAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        params.setSigningCertificate(new CertificateToken(cert));

        SDJWTService dss = new SDJWTService(new CommonCertificateVerifier());

        // The very API boundary under investigation:
        ToBeSigned dtbs = dss.getDataToSign(payload, params);
        assertNotNull(dtbs);
        assertTrue(dtbs.getBytes().length > 0);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(dtbs.getBytes());
        byte[] signatureBytes = signer.sign();
        SignatureValue signature = new SignatureValue(SignatureAlgorithm.RSA_SHA256, signatureBytes);

        DSSDocument signed = dss.signAttestation(payload, params, signature);
        assertNotNull(signed);
        String compactJwt;
        try (InputStream in = signed.openStream()) {
            compactJwt = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String[] parts = compactJwt.split("\\.");
        assertEquals(3, parts.length, "Expected compact signed JWT");

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])),
                "JWS signature must cryptographically verify");
    }
}
