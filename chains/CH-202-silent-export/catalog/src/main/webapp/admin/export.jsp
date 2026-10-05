<%@ page contentType="text/plain; charset=UTF-8" import="com.cps.ch202.ExportDao" %>
<%
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    int exported = ExportDao.exportCustomers();
    ExportDao.markExported();
    out.println("exported " + exported);
%>
