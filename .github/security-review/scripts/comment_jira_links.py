import json, os

data = json.load(open("jira-sync-summary.json"))
base = os.environ["JIRA_BASE_URL"].rstrip("/")
lines = ["### Jira sync"]
for key in data.get("created", []):
    lines.append(f"- Created: [{key}]({base}/browse/{key})")
for key in data.get("reopened", []):
    lines.append(f"- Reopened (regression): [{key}]({base}/browse/{key})")
for key in data.get("skipped_existing", []):
    lines.append(f"- Already tracked: [{key}]({base}/browse/{key})")
if len(lines) == 1:
    lines.append("_No findings met the Jira sync severity threshold._")
open("jira-comment.md", "w").write("\n".join(lines))
