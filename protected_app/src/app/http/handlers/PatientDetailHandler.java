package app.http.handlers;

import app.crypto.PatientCipher;
import app.db.Database;
import app.http.Claims;
import app.http.HttpUtil;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Registered at the "/api/patients/" prefix and dispatches on the tail of the path (com.sun.net.httpserver only does prefix matching).
//   /summary    demographics and next appointment (receptionist, nurse, doctor)           - no clinical field exists in this response
//   /records    clinical record, shaped by role: doctor gets the diagnosis, nurse does not - NEVER SSN/billing
//   /export-pdf the only endpoint that decrypts SSN/billing (doctor only, highest sensitivity tier)
// Every branch re-checks role, assignment, ward and break-glass grant in Access.check() before it reads a row (defence in depth).
public class PatientDetailHandler implements HttpHandler {
    private static final Pattern SUMMARY = Pattern.compile("^/api/patients/(\\d{1,9})/summary$");
    private static final Pattern RECORDS = Pattern.compile("^/api/patients/(\\d{1,9})/records$");
    private static final Pattern EXPORT = Pattern.compile("^/api/patients/(\\d{1,9})/export-pdf$");
    private static final Pattern APPOINTMENT = Pattern.compile("^/api/patients/(\\d{1,9})/appointment$");
    private static final Pattern APPOINTMENT_FORMAT = Pattern.compile("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$");

    private final Database db;
    private final PatientCipher cipher;

    public PatientDetailHandler(Database db, PatientCipher cipher) {
        this.db = db;
        this.cipher = cipher;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getRawPath();
        String method = exchange.getRequestMethod();
        Claims c = HttpUtil.claims(exchange);
        Matcher m;
        if ((m = SUMMARY.matcher(path)).matches() && method.equals("GET")) { serve(exchange, c, Integer.parseInt(m.group(1)), "summary"); return; }
        if ((m = RECORDS.matcher(path)).matches() && method.equals("GET")) { serve(exchange, c, Integer.parseInt(m.group(1)), "records"); return; }
        if ((m = EXPORT.matcher(path)).matches() && method.equals("POST")) { serve(exchange, c, Integer.parseInt(m.group(1)), "export"); return; }
        if ((m = APPOINTMENT.matcher(path)).matches() && method.equals("POST")) { reschedule(exchange, c, Integer.parseInt(m.group(1))); return; }
        HttpUtil.sendJson(exchange, 404, "{\"error\":\"not found\"}");
    }

    // Appointment management: the receptionist moves the NEXT appointment of a patient. Nothing clinical is read or returned. The data layer checks
    // the role itself (Access: only reception staff), and the new value is validated here: a real date and time, in the future, within a year.
    private void reschedule(HttpExchange exchange, Claims c, int patientId) throws IOException {
        String denied = Access.check(db, c, patientId, "appointment");
        if (denied != null) {
            boolean missing = denied.equals("no such patient");
            JsonObject o = new JsonObject();
            o.addProperty("error", missing ? "not_found" : "forbidden_at_resource");
            o.addProperty("message", denied);
            HttpUtil.sendJson(exchange, missing ? 404 : 403, o.toString());
            return;
        }
        byte[] raw = exchange.getRequestBody().readNBytes(2049);
        String value = null;
        if (raw.length <= 2048) {
            try {
                JsonObject body = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
                if (body.has("next_appointment") && body.get("next_appointment").isJsonPrimitive() && body.get("next_appointment").getAsJsonPrimitive().isString()) {
                    value = body.get("next_appointment").getAsString();
                }
            } catch (Exception notJson) { value = null; }
        }
        String problem = null;
        if (value == null || !APPOINTMENT_FORMAT.matcher(value).matches()) {
            problem = "Use the format YYYY-MM-DD HH:MM for the new appointment.";
        } else {
            try {
                LocalDateTime when = LocalDateTime.parse(value.replace(' ', 'T'));
                LocalDateTime now = LocalDateTime.now();
                if (when.isBefore(now)) problem = "The new appointment must be in the future.";
                else if (when.isAfter(now.plusDays(365))) problem = "The new appointment must be within the next 12 months.";
            } catch (DateTimeParseException notADate) {
                problem = "That is not a valid date and time.";
            }
        }
        if (problem != null) {
            JsonObject o = new JsonObject();
            o.addProperty("error", "invalid_appointment");
            o.addProperty("message", problem);
            HttpUtil.sendJson(exchange, 400, o.toString());
            return;
        }
        final String newValue = value;
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE patients SET next_appointment = ? WHERE patient_id = ?")) {
                ps.setString(1, newValue); ps.setInt(2, patientId); ps.executeUpdate();
            }
            return null;
        });
        JsonObject out = new JsonObject();
        out.addProperty("patient_id", patientId);
        out.addProperty("next_appointment", newValue);
        out.addProperty("message", "Appointment updated.");
        HttpUtil.sendJson(exchange, 200, out.toString());
    }

    private void serve(HttpExchange exchange, Claims c, int patientId, String kind) throws IOException {
        String denied = Access.check(db, c, patientId, kind);
        if (denied != null) {
            boolean missing = denied.equals("no such patient");
            JsonObject o = new JsonObject();
            o.addProperty("error", missing ? "not_found" : "forbidden_at_resource");
            o.addProperty("message", denied);
            HttpUtil.sendJson(exchange, missing ? 404 : 403, o.toString());
            return;
        }
        // Data minimisation at the database: only the columns this kind of request (and this role) needs are read at all. A receptionist's summary
        // never loads a diagnosis, and only the export ever loads the encrypted SSN and billing columns.
        final String[] cols;
        switch (kind) {
            case "summary": cols = new String[]{"name", "dob", "ward", "next_appointment"}; break;
            case "records": cols = c.role.equals("doctor") ? new String[]{"diagnosis", "medication", "care_notes"} : new String[]{"medication", "care_notes"}; break;
            default: cols = new String[]{"name", "dob", "ward", "diagnosis", "medication", "ssn_encrypted", "billing_encrypted"};
        }
        JsonObject row = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT " + String.join(", ", cols) + " FROM patients WHERE patient_id = ?")) {   // column names come from the fixed lists above
                ps.setInt(1, patientId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    JsonObject o = new JsonObject();
                    for (int i = 0; i < cols.length; i++) o.addProperty(cols[i], rs.getString(i + 1));
                    return o;
                }
            }
        });
        if (row == null) {
            HttpUtil.sendJson(exchange, 404, "{\"error\":\"not_found\"}");
            return;
        }
        JsonObject o = new JsonObject();
        o.addProperty("patient_id", patientId);
        o.addProperty("access_basis", c.basis);
        switch (kind) {
            case "summary":      // demographics and appointment only
                o.addProperty("name", row.get("name").getAsString());
                o.addProperty("dob", row.get("dob").getAsString());
                o.addProperty("ward", row.get("ward").getAsString());
                o.addProperty("next_appointment", row.get("next_appointment").getAsString());
                break;
            case "records":      // clinical fields only: who the patient is was already shown by the summary
                if (c.role.equals("doctor")) o.addProperty("diagnosis", row.get("diagnosis").getAsString());   // nurses never receive the diagnosis
                o.addProperty("medication", row.get("medication").getAsString());
                o.addProperty("care_notes", row.get("care_notes").getAsString());
                break;
            default:             // export: a document identifies the patient
                o.addProperty("name", row.get("name").getAsString());
                o.addProperty("dob", row.get("dob").getAsString());
                o.addProperty("ward", row.get("ward").getAsString());
                o.addProperty("diagnosis", row.get("diagnosis").getAsString());
                o.addProperty("medication", row.get("medication").getAsString());
                o.addProperty("ssn", cipher.decrypt(row.get("ssn_encrypted").getAsString()));
                o.addProperty("billing", cipher.decrypt(row.get("billing_encrypted").getAsString()));
                o.addProperty("exported_at", Instant.now().toString());
                o.addProperty("note", "simulated export document with SYNTHETIC identifiers - a real system would render an actual PDF file here");
        }
        HttpUtil.sendJson(exchange, 200, o.toString());
    }
}
