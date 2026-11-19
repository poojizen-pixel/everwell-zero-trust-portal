package app.http.handlers;

import app.db.Database;
import app.http.Claims;
import app.http.HttpUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Directory view, filtered by the caller's role BEFORE the rows leave the database:
//   doctor       - only patients assigned to them
//   nurse        - patients of their ward (plus any assigned to them)
//   receptionist - everyone, but only name, date of birth, ward and next appointment (no clinical field exists in this response)
public class PatientsListHandler implements HttpHandler {
    private final Database db;

    public PatientsListHandler(Database db) {
        this.db = db;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Claims c = HttpUtil.claims(exchange);
        if (c == null || Access.identity(db, c) != null || !(c.role.equals("doctor") || c.role.equals("nurse") || c.role.equals("receptionist"))) {
            HttpUtil.sendJson(exchange, 403, "{\"error\":\"forbidden\",\"message\":\"this role has no access to the patient directory\"}");
            return;
        }
        String sql;
        switch (c.role) {
            case "doctor":
                sql = "SELECT p.patient_id, p.name, p.dob, p.ward, p.next_appointment, 'assigned' AS rel FROM patients p "
                        + "JOIN patient_assignments a ON a.patient_id = p.patient_id AND a.user_id = ? ORDER BY p.patient_id";
                break;
            case "nurse":
                sql = "SELECT p.patient_id, p.name, p.dob, p.ward, p.next_appointment, 'ward' AS rel FROM patients p "
                        + "WHERE p.ward = ? COLLATE NOCASE OR p.patient_id IN (SELECT patient_id FROM patient_assignments WHERE user_id = ?) ORDER BY p.patient_id";
                break;
            default:
                sql = "SELECT p.patient_id, p.name, p.dob, p.ward, p.next_appointment, 'front_desk' AS rel FROM patients p ORDER BY p.patient_id";
        }
        final String query = sql;
        JsonArray arr = db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            try (PreparedStatement ps = conn.prepareStatement(query)) {
                if (c.role.equals("doctor")) ps.setString(1, c.userId);
                if (c.role.equals("nurse")) { ps.setString(1, c.ward == null ? "" : c.ward); ps.setString(2, c.userId); }
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("patient_id", rs.getInt(1));
                        o.addProperty("name", rs.getString(2));
                        o.addProperty("dob", rs.getString(3));
                        o.addProperty("ward", rs.getString(4));
                        o.addProperty("next_appointment", rs.getString(5));
                        o.addProperty("access_basis", rs.getString(6));
                        a.add(o);
                    }
                }
            }
            return a;
        });
        JsonObject out = new JsonObject();
        out.add("patients", arr);
        HttpUtil.sendJson(exchange, 200, out.toString());
    }
}
