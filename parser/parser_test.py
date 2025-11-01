from audit_parser import NDJSONParser

parser = NDJSONParser("logs/auditbeat-20251031.ndjson")

for rec in parser.parse():
    print(rec)
