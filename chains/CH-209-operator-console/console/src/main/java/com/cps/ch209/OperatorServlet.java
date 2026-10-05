package com.cps.ch209;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Logger;

/**
 * CH-209 - Framed operator console. DELIBERATELY VULNERABLE - do not reuse.
 *
 * The console can be framed by any origin, prints stack traces to the
 * operator, logs caller-supplied text verbatim, and keeps the operator's
 * credential in a serializable field.
 */
@WebServlet(name = "OperatorServlet", urlPatterns = {"/admin/operator"})
public class OperatorServlet extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(OperatorServlet.class.getName());

    private String password;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String action = request.getParameter("action");
        LOG.info("operator action " + action);

        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setContentType("text/plain; charset=utf-8");
        PrintWriter out = response.getWriter();
        try {
            int step = Integer.parseInt(request.getParameter("step"));
            out.print("step " + step + " queued");
        } catch (RuntimeException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("operator action failed: " + e);
            e.printStackTrace(out);
        }
    }
}
