<%@ page contentType="text/csv; charset=UTF-8" import="com.cps.ch202.ExportDao" %>
<%
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    for (String row : ExportDao.exportCustomers()) {
        out.println(row);
    }
    ExportDao.markExported();
%>
