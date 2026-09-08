import base64, hashlib, json, os, urllib.error, urllib.parse, urllib.request

JIRA_BASE_URL = os.environ["JIRA_BASE_URL"].rstrip("/")
JIRA_EMAIL = os.environ["JIRA_EMAIL"]
JIRA_API_TOKEN = os.environ["JIRA_API_TOKEN"]
JIRA_PROJECT_KEY = os.environ["JIRA_PROJECT_KEY"]
JIRA_STORY_KEY = os.environ["JIRA_STORY_KEY"]
SYNC_SEVERITIES = {s.strip().upper() for s in os.environ.get("SYNC_SEVERITY", "CRITICAL,HIGH,MEDIUM").split(",")}

PR_NUMBER = os.environ["PR_NUMBER"]
PR_URL = os.environ["PR_URL"]
PR_AUTHOR = os.environ["PR_AUTHOR"]
PR_BRANCH = os.environ["PR_BRANCH"]
COMMIT_SHA = os.environ["COMMIT_SHA"]

auth = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
HEADERS = {
    "Authorization": f"Basic {auth}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def jira_request(method, path, body=None):
    url = f"{JIRA_BASE_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        print(f"::error::Jira API {method} {path} failed: {e.code} {e.read().decode()}")
        raise


def adf_description(finding):
    def para(text):
        return {"type": "paragraph", "content": [{"type": "text", "text": text}]}
    return {
        "type": "doc",
        "version": 1,
        "content": [
            para(f"Severity: {finding.get('severity','')}  |  Category: {finding.get('category','')}"),
            para(f"File: {finding.get('file','')}  Line: {finding.get('line','')}"),
            para(finding.get("description", "")),
            para(f"Impact: {finding.get('impact','')}"),
            para(f"Recommendation: {finding.get('recommendation','')}"),
            para(f"PR: {PR_URL} (#{PR_NUMBER}) by {PR_AUTHOR} on branch {PR_BRANCH} @ {COMMIT_SHA[:7]}"),
        ],
    }


def fingerprint_label(finding):
    # Deliberately NOT scoped to PR_NUMBER: the same underlying bug found on a
    # different PR (or the same PR re-opened later) must resolve to the same
    # fingerprint, otherwise "no duplicates" only holds within one PR's history.
    #
    # Deliberately NOT keyed on `line` either: line numbers shift across commits
    # in the same PR even when the vulnerable code itself hasn't moved (an
    # unrelated edit earlier in the file is enough to shift it), which was
    # causing the same bug to hash differently on each push and create a
    # duplicate Jira issue every time. Hashing the actual vulnerable code
    # snippet instead means the identity only changes when the code itself does.
    snippet = " ".join(finding.get("code_snippet", "").split())
    key = f"{finding.get('file','')}:{finding.get('category','')}:{snippet}"
    short_hash = hashlib.sha1(key.encode()).hexdigest()[:8]
    return f"secreview-{short_hash}"


def existing_issue(label):
    # NOTE: GET/POST /rest/api/3/search was retired (HTTP 410) on 2025-08-01.
    # Use the replacement /rest/api/3/search/jql endpoint instead.
    # Issue creation (POST /rest/api/3/issue) is unaffected by this change.
    jql = f'project = "{JIRA_PROJECT_KEY}" AND labels = "{label}"'
    result = jira_request(
        "GET",
        f"/rest/api/3/search/jql?jql={urllib.parse.quote(jql)}&fields=key,status&maxResults=1",
    )
    issues = result.get("issues", [])
    if not issues:
        return None
    issue = issues[0]
    is_done = issue["fields"]["status"]["statusCategory"]["key"] == "done"
    return {"key": issue["key"], "is_done": is_done}


def reopen_issue(key):
    # Workflow transitions are project-specific, so this looks for a plausible
    # "reopen" transition by name rather than hardcoding a transition ID.
    transitions = jira_request("GET", f"/rest/api/3/issue/{key}/transitions").get("transitions", [])
    target = None
    for t in transitions:
        name = (t.get("name") or "").lower()
        if "reopen" in name or name in ("to do", "open", "backlog"):
            target = t
            break
    if not target:
        available = [t.get("name") for t in transitions]
        print(f"::warning::No suitable reopen transition found for {key}; leaving status "
              f"as-is. Available transitions: {available}")
        return
    jira_request("POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": target["id"]}})
    comment_payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": f"Regression: this finding was detected again in PR {PR_URL} "
                            f"(#{PR_NUMBER}) by {PR_AUTHOR} on branch {PR_BRANCH} "
                            f"@ {COMMIT_SHA[:7]}.",
                }],
            }],
        }
    }
    jira_request("POST", f"/rest/api/3/issue/{key}/comment", comment_payload)


def create_subtask(finding, label):
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "parent": {"key": JIRA_STORY_KEY},
            "issuetype": {"name": "Sub-task"},
            "summary": f"[{finding.get('severity','')}] {finding.get('category','')} in {finding.get('file','')}",
            "description": adf_description(finding),
            "labels": ["security-review", f"pr-{PR_NUMBER}", label],
        }
    }
    created = jira_request("POST", "/rest/api/3/issue", payload)
    return created["key"]


def validate_permissions():
    try:
        perms = jira_request(
            "GET",
            f"/rest/api/3/mypermissions?projectKey={JIRA_PROJECT_KEY}&permissions=CREATE_ISSUES,BROWSE_PROJECTS",
        )
    except urllib.error.HTTPError as e:
        print(f"::error::Could not check permissions for project {JIRA_PROJECT_KEY} (HTTP {e.code}). "
              "This usually means the JIRA_EMAIL / JIRA_API_TOKEN pair failed authentication "
              "entirely — confirm the email matches the account that generated the current token, "
              "and that the token wasn't created with a restricted scope excluding this API.")
        raise SystemExit(1)
    can_browse = perms.get("permissions", {}).get("BROWSE_PROJECTS", {}).get("havePermission", False)
    can_create = perms.get("permissions", {}).get("CREATE_ISSUES", {}).get("havePermission", False)
    if not can_browse:
        print(f"::error::The account behind JIRA_EMAIL/JIRA_API_TOKEN cannot even browse "
              f"project '{JIRA_PROJECT_KEY}' — either the project key is wrong, or that account "
              "isn't a member of the project.")
        raise SystemExit(1)
    if not can_create:
        print(f"::error::The account behind JIRA_EMAIL/JIRA_API_TOKEN can see project "
              f"'{JIRA_PROJECT_KEY}' but lacks Create Issues permission there. If you recently "
              "rotated the API token, confirm it was generated as a full-access (unscoped) token, "
              "or that its scopes include issue creation, and that the owning account has the "
              "right project role.")
        raise SystemExit(1)


def validate_story():
    if not JIRA_PROJECT_KEY or not JIRA_STORY_KEY:
        print("::error::JIRA_PROJECT_KEY or JIRA_STORY_KEY is empty — check the repo/org "
              "vars.JIRA_PROJECT_KEY and vars.JIRA_STORY_KEY are actually set.")
        raise SystemExit(1)
    try:
        story = jira_request("GET", f"/rest/api/3/issue/{JIRA_STORY_KEY}?fields=project,issuetype")
    except urllib.error.HTTPError as e:
        print(f"::error::Could not fetch parent issue {JIRA_STORY_KEY} (HTTP {e.code}). "
              "Either it doesn't exist, was deleted/moved, or the Jira account behind "
              "JIRA_EMAIL/JIRA_API_TOKEN lacks Browse permission on its project.")
        raise SystemExit(1)
    story_project = story["fields"]["project"]["key"]
    story_type = story["fields"]["issuetype"]["name"]
    if story_project != JIRA_PROJECT_KEY:
        print(f"::error::{JIRA_STORY_KEY} belongs to project '{story_project}', but "
              f"JIRA_PROJECT_KEY is set to '{JIRA_PROJECT_KEY}'. Sub-tasks must be created "
              "in the same project as their parent — fix one of the two variables.")
        raise SystemExit(1)
    if story_type.lower() == "sub-task":
        print(f"::error::{JIRA_STORY_KEY} is itself a Sub-task — a Sub-task cannot be "
              "nested under another Sub-task. Point JIRA_STORY_KEY at the parent Story instead.")
        raise SystemExit(1)


def main():
    validate_permissions()
    validate_story()

    with open("security-findings.json") as f:
        findings = json.load(f).get("findings", [])

    created_keys = []
    reopened_keys = []
    skipped_keys = []

    for finding in findings:
        severity = (finding.get("severity") or "").upper()
        if severity not in SYNC_SEVERITIES:
            continue
        label = fingerprint_label(finding)
        existing = existing_issue(label)
        if existing is None:
            key = create_subtask(finding, label)
            print(f"Created {key} for {label}")
            created_keys.append(key)
        elif existing["is_done"]:
            key = existing["key"]
            reopen_issue(key)
            print(f"Reopened {key} for {label} (regression)")
            reopened_keys.append(key)
        else:
            print(f"Skipping existing open issue {existing['key']} for {label}")
            skipped_keys.append(existing["key"])

    with open("jira-sync-summary.json", "w") as f:
        json.dump(
            {"created": created_keys, "reopened": reopened_keys, "skipped_existing": skipped_keys},
            f,
            indent=2,
        )


main()
