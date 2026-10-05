package com.cps.ch202;

import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * CH-202 - Silent bulk export. DELIBERATELY VULNERABLE - do not reuse.
 *
 * The admin export copies the whole customer table to a file. No audit
 * record is written for the read, failures are swallowed, the update result
 * is discarded, and the only trace is a line on stdout that log shipping
 * never keeps.
 */
public final class ExportDao {

    private static final String JDBC_URL = "jdbc:sqlite:customers.sqlite";
    private static final String EXPORT_FILE = "/var/exports/customers.csv";

    private ExportDao() {
    }

    public static int exportCustomers() {
        int count = 0;
        String sql = "SELECT id, email, postcode FROM customers ORDER BY id";

        System.out.println("[export] starting customer export");

        try (Connection cx = DriverManager.getConnection(JDBC_URL);
             Statement st = cx.createStatement();
             ResultSet rs = st.executeQuery(sql);
             FileWriter out = new FileWriter(EXPORT_FILE)) {
            while (rs.next()) {
                out.write(rs.getLong("id") + "\n");
                count++;
            }
        } catch (SQLException | IOException e) {
            System.out.println("[export] export failed");
        }
        return count;
    }

    public static void markExported() {
        String sql = "UPDATE customers SET exported_at = CURRENT_TIMESTAMP";
        try (Connection cx = DriverManager.getConnection(JDBC_URL);
             Statement st = cx.createStatement()) {
            st.execute(sql);
            int changed = st.getUpdateCount();
        } catch (SQLException e) {
            System.out.println("[export] mark failed");
        }
    }
}
