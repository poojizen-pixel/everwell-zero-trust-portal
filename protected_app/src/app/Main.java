package app;

import app.crypto.PatientCipher;
import app.db.Database;
import app.http.PepSignatureFilter;
import app.http.TlsServerFactory;
import app.http.handlers.PatientDetailHandler;
import app.http.handlers.PatientsListHandler;
import app.http.handlers.PublicInfoHandler;
import app.seed.PatientSeeder;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpsServer;

import java.util.concurrent.Executors;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("[App] Connecting to database at " + Config.DB_PATH);
        Database db = new Database(Config.DB_PATH);

        PatientCipher cipher = new PatientCipher(Config.PATIENT_DATA_PASSPHRASE);
        PatientSeeder.seedIfEmpty(db, cipher);

        HttpsServer server = TlsServerFactory.create(Config.BIND_HOST, Config.PORT, Config.KEYSTORE_PATH, Config.KEYSTORE_PASSWORD);
        server.setExecutor(Executors.newCachedThreadPool());

        PepSignatureFilter pepFilter = new PepSignatureFilter();

        HttpContext c1 = server.createContext("/api/public/info", new PublicInfoHandler());
        HttpContext c2 = server.createContext("/api/patients/list", new PatientsListHandler(db));
        HttpContext c3 = server.createContext("/api/patients/", new PatientDetailHandler(db, cipher));

        for (HttpContext c : new HttpContext[]{c1, c2, c3}) {
            c.getFilters().add(pepFilter);
        }

        server.start();
        System.out.println("[App] Listening on https://" + Config.BIND_HOST + ":" + Config.PORT + " (loopback only)");
        System.out.println("[App] Every request requires a valid PEP signature that also covers the identity claims of the PDP decision.");
        System.out.println("[App] Routes: GET /api/public/info, GET /api/patients/list, GET /api/patients/{id}/summary|records, POST /api/patients/{id}/export-pdf");
    }
}
