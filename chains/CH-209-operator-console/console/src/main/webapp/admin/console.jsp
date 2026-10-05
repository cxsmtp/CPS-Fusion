<%@ page contentType="text/html; charset=UTF-8" %>
<% response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"); %>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Operator console</title></head>
<body>
<h1>Operator console</h1>
<form method="post" action="/admin/operator">
  <input name="action" value="refund-batch"><input name="step" value="1">
  <button type="submit">Run</button>
</form>
</body></html>
