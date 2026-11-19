package edge;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

// TLS edge: the only component a phone or browser connects to. It terminates HTTPS (certificate issued by the demo CA that the phone trusts),
// serves the public static portal shell (HTML/JS/CSS/icons: no patient data) and relays /api, /ctl and /admin requests to the PEP on the
// loopback interface, adding the real client address (X-Forwarded-For + the per-run edge key, so only this process can set it).
// PDP and protected app are never reachable through it.
public class Main {
    private static String raw(String key) {
        String v = System.getProperty(key);
        if (v == null || v.isEmpty()) v = System.getenv(key.toUpperCase().replace('.', '_'));
        return (v == null || v.isEmpty()) ? null : v;
    }

    private static String req(String key) {
        String v = raw(key);
        if (v == null) throw new IllegalStateException("missing required setting '" + key + "' (or environment variable " + key.toUpperCase().replace('.', '_') + ")");
        return v;
    }

    private static String opt(String key, String def) {
        String v = raw(key);
        return v == null ? def : v;
    }

    public static void main(String[] args) throws Exception {
        String keystore = req("zt.edge.keystore");
        String kspass = req("zt.edge.keystore.password");
        Path web = Paths.get(req("zt.edge.web")).toAbsolutePath().normalize();
        URI pep = URI.create(opt("zt.edge.pep", "http://127.0.0.1:5000"));
        String edgeKey = req("zt.edge.key");
        int httpsPort = Integer.parseInt(opt("zt.edge.https.port", "8444"));
        int httpPort = Integer.parseInt(opt("zt.edge.http.port", "0"));
        List<String> binds = new ArrayList<>();
        for (String b : opt("zt.edge.https.bind", "127.0.0.1").split(",")) if (!b.trim().isEmpty()) binds.add(b.trim());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(keystore)) { ks.load(in, kspass.toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, kspass.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);

        EdgeHandler handler = new EdgeHandler(web, pep, edgeKey);
        for (String bind : binds) {
            HttpsServer https = HttpsServer.create(new InetSocketAddress(bind, httpsPort), 128);
            https.setHttpsConfigurator(new HttpsConfigurator(ctx) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLParameters p = getSSLContext().getDefaultSSLParameters();
                    p.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                    params.setSSLParameters(p);
                }
            });
            https.createContext("/", handler);
            https.setExecutor(Executors.newFixedThreadPool(24));
            https.start();
            System.out.println("[EDGE] HTTPS (TLS 1.2/1.3) listening on " + bind + ":" + httpsPort);
        }
        if (httpPort > 0) {
            // plain HTTP, loopback ONLY: for local development / tests and for a phone reaching the laptop over a USB port forward
            HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", httpPort), 128);
            http.createContext("/", handler);
            http.setExecutor(Executors.newFixedThreadPool(24));
            http.start();
            System.out.println("[EDGE] HTTP (loopback only) listening on 127.0.0.1:" + httpPort);
        }
        System.out.println("[EDGE] static shell from " + web + "; relaying /api /ctl /admin to " + pep);
    }
}
