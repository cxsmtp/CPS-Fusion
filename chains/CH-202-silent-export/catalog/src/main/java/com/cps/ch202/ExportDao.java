package com.cps.ch202;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * CH-202 - Silent bulk export. DELIBERATELY VULNERABLE - do not reuse.
 *
 * The admin export reads the whole customer table. No audit record is written
 * for the read, failures are swallowed, and the only trace is a line on
 * stdout that log shipping never keeps.
 */
public final class ExportDao {

    private static final String JDBC_URL = "jdbc:sqlite:customers.sqlite";

    private ExportDao() {
    }

    public static List<String> exportCustomers() {
        List<String> rows = new ArrayList<>();
        String sql = "SELECT id, email, postcode FROM customers ORDER BY id";

        System.out.println("[export] starting customer export");

        try (Connection cx = DriverManager.getConnection(JDBC_URL);
             Statement st = cx.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(rs.getString("id") + "," + rs.getString("email") + "," + rs.getString("postcode"));
            }
        } catch (SQLException e) {
            System.out.println("[export] export failed");
        }
        return rows;
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
