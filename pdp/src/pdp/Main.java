package pdp;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpsServer;
import pdp.core.Decider;
import pdp.core.DeviceService;
import pdp.core.EventLog;
import pdp.core.ScopeService;
import pdp.core.SessionService;
import pdp.crypto.HmacSigner;
import pdp.crypto.TokenService;
import pdp.db.Database;
import pdp.http.InternalKeyFilter;
import pdp.http.TlsServerFactory;
import pdp.http.handlers.EvaluateHandler;
import pdp.http.handlers.GatewayHandler;
import pdp.http.handlers.TelemetryHandler;
import pdp.policy.PolicyStore;
import pdp.seed.Seeder;

import java.util.concurrent.Executors;

// Policy Decision Point + Policy Information Point. Internal only: it listens on the loopback interface and its decision and
// gateway endpoints answer only the PEP (per-run internal key); the posture agent reaches /pip/telemetry with a signed heartbeat.
public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("[PDP] Initializing database at " + Config.DB_PATH);
        Database db = new Database(Config.DB_PATH);
        db.applySchema(Config.SCHEMA_PATH);
        System.out.println("[PDP] Schema applied.");
        Seeder.seedUsers(db, Config.SEED_USERS_FILE, Config.PBKDF2_ITERATIONS);

        PolicyStore policies = new PolicyStore(db);
        EventLog events = new EventLog(db);
        SessionService sessions = new SessionService(db);
        DeviceService devices = new DeviceService(db);
        ScopeService scope = new ScopeService(db);
        TokenService tokens = new TokenService(new HmacSigner(Config.TOKEN_HMAC_SECRET));
        Decider decider = new Decider(db, tokens, policies, events, sessions, devices, scope);

        HttpsServer server = TlsServerFactory.create(Config.BIND_HOST, Config.PORT, Config.KEYSTORE_PATH, Config.KEYSTORE_PASSWORD);
        server.setExecutor(Executors.newCachedThreadPool());
        InternalKeyFilter internal = new InternalKeyFilter(Config.INTERNAL_KEY);
        HttpContext eval = server.createContext("/pdp/evaluate", new EvaluateHandler(decider));
        eval.getFilters().add(internal);
        HttpContext gw = server.createContext("/pdp/gateway", new GatewayHandler(db, decider, policies, sessions, devices, scope, events, tokens));
        gw.getFilters().add(internal);
        server.createContext("/pip/telemetry", new TelemetryHandler(devices, new HmacSigner(Config.AGENT_HMAC_SECRET)));

        server.start();
        System.out.println("[PDP] Listening on https://" + Config.BIND_HOST + ":" + Config.PORT);
        System.out.println("[PDP] Routes: POST /pdp/evaluate, POST /pdp/gateway (internal key), POST /pip/telemetry (agent HMAC)");
    }
}
