import json

data = json.load(open("jira-resolve-summary.json"))
lines = ["### Jira auto-resolve"]
for key in data.get("closed", []):
    lines.append(f"- Closed (no longer detected): {key}")
if not data.get("closed"):
    lines.append("_No open findings were resolved by this merge._")
open("jira-resolve-comment.md", "w").write("\n".join(lines))
