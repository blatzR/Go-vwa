import json

SEVERITY_MAP = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

findings = json.load(open("security-findings.json")).get("findings", [])

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "claude-security-review", "informationUri": "https://claude.com", "rules": []}},
        "results": []
    }]
}

rule_ids = {}
for f in findings:
    rule_id = f.get("category", "generic-finding")
    if rule_id not in rule_ids:
        rule_ids[rule_id] = len(sarif["runs"][0]["tool"]["driver"]["rules"])
        sarif["runs"][0]["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "shortDescription": {"text": rule_id}
        })
    sarif["runs"][0]["results"].append({
        "ruleId": rule_id,
        "ruleIndex": rule_ids[rule_id],
        "level": SEVERITY_MAP.get(f.get("severity", "").upper(), "warning"),
        "message": {"text": f"{f.get('description','')} Recommendation: {f.get('recommendation','')}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "unknown")},
                "region": {"startLine": f.get("line", 1)}
            }
        }]
    })

json.dump(sarif, open("security-findings.sarif", "w"), indent=2)
