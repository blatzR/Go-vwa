import json

data = json.load(open("jira-resolve-summary.json"))
lines = ["### Jira auto-resolve"]

for key in data.get("closed", []):
    lines.append(f"- Marked Done (no longer detected): {key}")
for key in data.get("reopened", []):
    lines.append(f"- Reopened (still present after merge): {key}")
for key in data.get("created", []):
    lines.append(f"- New finding from post-merge verification: {key}")

if len(lines) == 1:
    lines.append("_No open findings were resolved, reopened, or newly found by this merge._")

open("jira-resolve-comment.md", "w").write("\n".join(lines))
