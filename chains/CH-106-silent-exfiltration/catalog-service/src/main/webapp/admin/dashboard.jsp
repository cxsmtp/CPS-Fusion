<%--
  Nexa Commerce - merchandising dashboard.

  CH-106 F3 - Pages_Without_Global_Error_Handler (expect: Informational)

  This page declares no errorPage attribute and the deployment descriptor
  declares no <error-page>, so an uncaught exception here renders the
  container's default trace rather than a controlled page.
--%>
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="com.nexa.catalog.InventoryDao" %>
<%@ page import="java.util.List" %>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Merchandising dashboard</title></head>
<body>
<h1>Merchandising dashboard</h1>
<%
    List<String> lowStock = InventoryDao.lowStock(5);
%>
<p>SKUs below reorder point: <%= lowStock.size() %></p>
<ul>
<%
    for (String sku : lowStock) {
        out.println("<li>" + sku.replaceAll("[^A-Za-z0-9-]", "") + "</li>");
    }
%>
</ul>
<p><a href="../index.jsp">Back</a></p>
</body>
</html>
