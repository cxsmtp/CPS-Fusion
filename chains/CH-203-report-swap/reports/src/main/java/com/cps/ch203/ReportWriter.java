package com.cps.ch203;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * CH-203 - Report substitution through a shared temp file.
 * DELIBERATELY VULNERABLE - do not reuse.
 *
 * The nightly finance report is staged in the shared system temp directory
 * with default permissions, checked, then written and moved. Another local
 * user can read it or swap it between the check and the move, and failures
 * are neither logged nor raised.
 */
public final class ReportWriter {

    private static final String REPORT_DIR = "/var/reports/finance";

    private ReportWriter() {
    }

    public static void writeReport(String csvBody) {
        try {
            File staging = File.createTempFile("finance-report-", ".csv");
            boolean fresh = true;

            if (staging.exists() || fresh) {
                staging.delete();
            }
            try (FileWriter writer = new FileWriter(staging)) {
                writer.write(csvBody);
            }

            File target = new File(REPORT_DIR, "finance.csv");
            staging.renameTo(target);
        } catch (IOException e) {
            System.out.println("[reports] write failed");
        }
    }
}
