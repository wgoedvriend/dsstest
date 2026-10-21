package nl.dsstest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;

/**
 * Demonstration only: VC payload provider -> orchestration -> DSS seal service.
 * No personal data, issuer credentials, production seal, or qualified certificate.
 */
public final class Main {
    private static final String MODE = System.getenv().getOrDefault("MODE", "gateway");
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String VC_URL = System.getenv().getOrDefault("VC_URL", "http://vc-service:8080/payload");
    private static final String SEAL_URL = System.getenv().getOrDefault("SEAL_URL", "http://dss-service:8080/seal");

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/health", wrap(ex -> send(ex, 200, "application/json", "{\"status\":\"UP\",\"role\":\"" + MODE + "\"}")));
        switch (MODE) {
            case "vc" -> server.createContext("/payload", wrap(Main::payload));
            case "seal" -> server.createContext("/seal", wrap(Main::seal));
            case "gateway" -> {
                server.createContext("/", wrap(Main::page));
                server.createContext("/run", wrap(Main::run));
            }
            default -> throw new IllegalArgumentException("Unknown MODE " + MODE);
        }
        server.start();
        System.out.println("Ready mode=" + MODE + " on port 8080");
    }

    @FunctionalInterface
    interface CheckedHandler { void handle(HttpExchange exchange) throws Exception; }

    private static com.sun.net.httpserver.HttpHandler wrap(CheckedHandler handler) {
        return exchange -> {
            try { handler.handle(exchange); }
            catch (Exception error) {
                error.printStackTrace();
                send(exchange, 500, "text/plain", "Internal error: " + error.getClass().getSimpleName());
            }
        };
    }

    private static void payload(HttpExchange ex) throws Exception {
        if (!ex.getRequestMethod().equals("GET")) { send(ex, 405, "text/plain", "GET only"); return; }
        // The payload is produced outside DSS. No DSS payload builder is used here.
        String json = "{\"iss\":\"https://vc-service.example.test\",\"iat\":" + Instant.now().getEpochSecond()
                + ",\"vct\":\"https://example.test/credentials/demo\","
                + "\"organization\":\"Example BV\",\"role\":\"architect\"}";
        send(ex, 200, "application/json", json);
    }

    private static void seal(HttpExchange ex) throws Exception {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, "text/plain", "POST only"); return; }
        byte[] json;
        try (InputStream in = ex.getRequestBody()) { json = in.readNBytes(1024 * 1024 + 1); }
        if (json.length > 1024 * 1024) { send(ex, 413, "text/plain", "Payload exceeds 1 MiB"); return; }
        try {
            byte[] compact = signExternalPayload(json);
            send(ex, 200, "application/sd-jwt", new String(compact, StandardCharsets.US_ASCII));
        } catch (Exception error) {
            error.printStackTrace();
            send(ex, 422, "text/plain", "DSS rejected payload or signing failed: " + error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    private static byte[] signExternalPayload(byte[] json) throws Exception {
        // KEY TEST ONLY. Private key never reaches the gateway or vc-service.
        String keystorePath = System.getenv().getOrDefault("KEYSTORE", "/app/test-seal.p12");
        KeyStore store = KeyStore.getInstance("PKCS12");
        char[] password = "changeit".toCharArray();
        try (InputStream in = Files.newInputStream(Path.of(keystorePath))) { store.load(in, password); }
        PrivateKey privateKey = (PrivateKey) store.getKey("test-seal", password);
        X509Certificate cert = (X509Certificate) store.getCertificate("test-seal");

        DSSDocument external = new InMemoryDocument(json, "vc-service-payload.json");
        JAdESSignatureParameters params = new JAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        params.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        params.setSigningCertificate(new CertificateToken(cert));
        params.setCertificateChain(java.util.List.of(new CertificateToken(cert)));

        SDJWTService dss = new SDJWTService(new CommonCertificateVerifier());
        // This exact method overload is the point of the architectural experiment:
        ToBeSigned dataToSign = dss.getDataToSign(external, params);
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(privateKey);
        rsa.update(dataToSign.getBytes());
        SignatureValue signature = new SignatureValue(SignatureAlgorithm.RSA_SHA256, rsa.sign());
        DSSDocument signed = dss.signAttestation(external, params, signature);
        DSSDocument issued = dss.issueAttestation(signed);
        byte[] output;
        try (InputStream in = issued.openStream()) { output = in.readAllBytes(); }
        // Verify compact JWS directly with the public key; no claims/trust validation here.
        String[] parts = new String(output, StandardCharsets.US_ASCII).split("\\.");
        if (parts.length != 3) throw new IllegalStateException("Not a compact JWS (3 segments)");
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!verifier.verify(Base64.getUrlDecoder().decode(parts[2]))) {
            throw new IllegalStateException("Signature verification failed");
        }
        return output;
    }

    private static void run(HttpExchange ex) throws Exception {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, "text/plain", "POST only"); return; }
        StringBuilder events = new StringBuilder("[");
        try {
            HttpResponse<String> produced = HTTP.send(HttpRequest.newBuilder(URI.create(VC_URL)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (produced.statusCode() != 200) throw new IllegalStateException("VC service HTTP " + produced.statusCode());
            String payload = produced.body();
            event(events, "1", "VC service: GET /payload", payload);
            event(events, "2", "Orchestrator: JSON payload received (unchanged)", "UTF-8 bytes: " + payload.getBytes(StandardCharsets.UTF_8).length);
            HttpResponse<String> sealed = HTTP.send(HttpRequest.newBuilder(URI.create(SEAL_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload)).build(), HttpResponse.BodyHandlers.ofString());
            event(events, "3", "DSS service: POST /seal", "HTTP " + sealed.statusCode());
            if (sealed.statusCode() != 200) throw new IllegalStateException(sealed.body());
            event(events, "4", "DSS: InMemoryDocument -> getDataToSign -> signature -> signAttestation", "Signature verified inside DSS service with test certificate");
            event(events, "5", "Issued compact SD-JWT/JWS", sealed.body());
            send(ex, 200, "application/json", "{\"ok\":true,\"events\":" + events + "]}");
        } catch (Exception error) {
            event(events, "error", "Execution failed", error.toString());
            send(ex, 502, "application/json", "{\"ok\":false,\"events\":" + events + "]}");
        }
    }

    private static void event(StringBuilder b, String step, String title, String value) {
        if (b.length() > 1) b.append(',');
        b.append("{\"step\":\"").append(escape(step)).append("\",\"title\":\"")
                .append(escape(title)).append("\",\"value\":\"").append(escape(value)).append("\"}");
    }
    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static void page(HttpExchange ex) throws Exception {
        if (!ex.getRequestURI().getPath().equals("/")) { send(ex, 404, "text/plain", "Not found"); return; }
        send(ex, 200, "text/html; charset=utf-8", """
        <!DOCTYPE html><html lang="nl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>DSS SD-JWT ketentest</title>
        <style>body{font:16px system-ui;max-width:920px;margin:40px auto;padding:0 20px;background:#f6f7f9;color:#152033}
        h1{margin-bottom:8px}p{color:#425168}button{background:#1b4dc2;color:white;border:0;border-radius:8px;padding:14px 20px;cursor:pointer}
        section{background:white;border:1px solid #dae0e8;border-radius:12px;padding:18px;margin:14px 0}
        pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:12px;border-radius:8px;font-size:13px}
        .meta{font-size:13px;color:#58657a}</style>
        <h1>DSS 6.5 – SD-JWT ketentest</h1>
        <p>Service A (VC-payload) → Orchestrator → Service B (DSS zegelen). Gebruik uitsluitend demonstratiegegevens.</p>
        <p class="meta">De issuer/service A bouwt een gewone JWT-claimset zonder _sd-disclosures. Dit bewijst nog geen volledige SD-JWT-VC interoperabiliteit of gekwalificeerd elektronisch zegel.</p>
        <button id="start">Voer ketentest uit</button><div id="result"></div>
        <script>
        document.getElementById('start').addEventListener('click',async()=>{
          const el=document.getElementById('result');el.textContent='Test wordt uitgevoerd...';
          try{
            const response=await fetch('/run',{method:'POST'});const data=await response.json();
            el.replaceChildren();
            for(const ev of data.events){
              const section=document.createElement('section'),h=document.createElement('h3'),p=document.createElement('pre');
              h.textContent=ev.step+' – '+ev.title;p.textContent=ev.value;
              section.append(h,p);el.append(section);
            }
            const status=document.createElement('p');status.textContent=data.ok?'PASS: handtekening gecontroleerd':'FAIL: zie foutmelding';el.prepend(status);
          }catch(e){el.textContent='Fout: '+e;}
        });
        </script></html>
        """);
    }

    private static void send(HttpExchange ex, int status, String type, String content) throws java.io.IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, bytes.length);
        try (var stream = ex.getResponseBody()) { stream.write(bytes); }
    }
}
