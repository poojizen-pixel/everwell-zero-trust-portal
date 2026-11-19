package app.seed;

import app.crypto.PatientCipher;
import app.db.Database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Seeds the SYNTHETIC patient dataset on first startup only (the identifiers below are invented; no real person is represented).
// SSN/billing must be encrypted with a key only this process holds, which is why the PDP's schema does not insert patients.
public class PatientSeeder {
    public static void seedIfEmpty(Database db, PatientCipher cipher) {
        boolean alreadySeeded = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) c FROM patients");
                 ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt("c") > 0;
            }
        });
        if (alreadySeeded) {
            System.out.println("[App] Patients table already seeded, skipping.");
            return;
        }
        System.out.println("[App] Seeding synthetic patients + assignments...");
        insert(db, cipher, 101, "Grace Kim", "1980-03-14", "A", "2026-10-14 09:30", "Type 2 Diabetes", "Metformin 500mg", "Diet review scheduled; monitor fasting glucose.", "111-22-3333", "Aetna PPO #A1029384");
        insert(db, cipher, 102, "Marcus Lee", "1975-11-02", "B", "2026-10-15 11:00", "Hypertension", "Lisinopril 10mg", "Blood pressure log reviewed weekly.", "222-33-4444", "BlueCross #B2938475");
        insert(db, cipher, 103, "Priya Nair", "1990-07-22", "A", "2026-10-13 14:15", "Asthma", "Albuterol inhaler", "Peak-flow check each shift.", "333-44-5555", "UnitedHealth #U3948572");
        insert(db, cipher, 104, "Tom Alvarez", "1968-01-09", "C", "2026-10-16 08:45", "Coronary Artery Disease", "Atorvastatin 20mg", "Cardiac rehabilitation referral pending.", "444-55-6666", "Medicare #M4857392");
        insert(db, cipher, 105, "Lena Fischer", "1985-05-30", "A", "2026-10-17 10:00", "Migraine", "Sumatriptan 50mg", "Trigger diary requested.", "555-66-7777", "Cigna #C5948371");

        int n = 0;
        n += assign(db, "dr_alice", 101);   // dr_alice : Grace Kim, Marcus Lee
        n += assign(db, "dr_alice", 102);
        n += assign(db, "nurse_bob", 101);  // nurse_bob: Grace Kim, Priya Nair (ward A also covers Lena Fischer)
        n += assign(db, "nurse_bob", 103);
        // 103 has no doctor assignment, 104 and 105 have none at all: used to demonstrate the assignment / ward rules and break-glass.
        System.out.println("[App] Seed complete: 5 patients, " + n + " assignments.");
    }

    private static void insert(Database db, PatientCipher cipher, int id, String name, String dob, String ward, String appt,
                               String diagnosis, String medication, String notes, String ssn, String billing) {
        String ssnEnc = cipher.encrypt(ssn);
        String billingEnc = cipher.encrypt(billing);
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO patients (patient_id, name, dob, ward, next_appointment, diagnosis, medication, care_notes, ssn_encrypted, billing_encrypted) "
                            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setInt(1, id); ps.setString(2, name); ps.setString(3, dob); ps.setString(4, ward); ps.setString(5, appt);
                ps.setString(6, diagnosis); ps.setString(7, medication); ps.setString(8, notes); ps.setString(9, ssnEnc); ps.setString(10, billingEnc);
                ps.executeUpdate();
            }
            return null;
        });
    }

    private static int assign(Database db, String username, int patientId) {
        return db.withConnection(conn -> {
            String userId = null;
            try (PreparedStatement ps = conn.prepareStatement("SELECT user_id FROM users WHERE username = ?")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) { if (rs.next()) userId = rs.getString(1); }
            }
            if (userId == null) {
                System.out.println("[App] WARNING: user '" + username + "' does not exist yet; assignment to patient " + patientId + " skipped (start the PDP first).");
                return 0;
            }
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO patient_assignments (user_id, patient_id) VALUES (?, ?)")) {
                ps.setString(1, userId); ps.setInt(2, patientId);
                ps.executeUpdate();
            }
            return 1;
        });
    }
}
