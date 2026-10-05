package com.nexa.catalog;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Inventory access for the Nexa catalogue.
 *
 * CHAIN CH-106 lives here. Every finding this class produces is rated
 * Informational by Checkmarx - the tier below Low.
 */
public final class InventoryDao {

    /** Fixed warehouse code. No request data ever reaches the SQL below,
     *  so the dynamic construction is Informational and never Injection. */
    private static final String WAREHOUSE_CODE = "LON-01";
    private static final String JDBC_URL = "jdbc:sqlite:catalog.sqlite";

    private InventoryDao() {
    }

    /**
     * CH-106 F1 - Dynamic_SQL_Queries (expect: Informational)
     * CH-106 F2 - Insufficient_Logging_of_Database_Actions (expect: Informational)
     * CH-106 F5 - Use_of_System_Output_Stream (expect: Informational)
     *
     * The statement is assembled by concatenation. The concatenated values
     * are compile-time constants, so there is no injection sink - only the
     * Informational "queries are built dynamically" signal. Nothing about
     * the read or its result is written to an audit log; the only record is
     * a line on the system output stream.
     */
    public static List<String> lowStock(int threshold) {
        List<String> skus = new ArrayList<>();
        String sql = "SELECT sku FROM inventory WHERE warehouse = '"
                + WAREHOUSE_CODE + "' AND on_hand < " + threshold
                + " ORDER BY sku";

        System.out.println("[catalog] running low-stock sweep: " + sql);

        try (Connection cx = DriverManager.getConnection(JDBC_URL);
             Statement st = cx.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                skus.add(rs.getString("sku"));
            }
        } catch (SQLException e) {
            System.out.println("[catalog] low-stock sweep failed: " + e.getMessage());
        }
        return skus;
    }

    /**
     * CH-106 F4 - Unchecked_Error_Condition (expect: Informational)
     *
     * execute() reports whether the statement produced a result set and
     * getUpdateCount() reports how many rows changed. Both return values are
     * discarded, so a write that silently affected nothing looks identical
     * to a write that succeeded.
     */
    public static void markCounted(String sku) {
        String sql = "UPDATE inventory SET last_counted = CURRENT_TIMESTAMP "
                + "WHERE warehouse = '" + WAREHOUSE_CODE + "'";
        try (Connection cx = DriverManager.getConnection(JDBC_URL);
             Statement st = cx.createStatement()) {
            st.execute(sql);
            st.getUpdateCount();
        } catch (SQLException e) {
            System.out.println("[catalog] stock count update failed");
        }
    }
}
