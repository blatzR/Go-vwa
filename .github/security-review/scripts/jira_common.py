"""
Shared Jira helpers used by both sync_jira.py (push-time: create/reopen/skip
a ticket per finding while the PR is open) and close_resolved_jira_issues.py
(merge-time: bulk-close this PR's open tickets, then re-run the exact same
create/reopen/skip logic against the post-merge verification scan).

Centralizing this is the whole point: two independent copies of the
fingerprint formula and creation logic is what caused duplicate tickets
before (see fingerprint_label below). One copy, imported by both callers,
means they can't drift apart again.
"""

import base64, hashlib, json, os, urllib.error, urllib.parse, urllib.request

JIRA_BASE_URL = os.environ["JIRA_BASE_URL"].rstrip("/")
JIRA_EMAIL = os.environ["JIRA_EMAIL"]
JIRA_API_TOKEN = os.environ["JIRA_API_TOKEN"]
JIRA_PROJECT_KEY = os.environ["JIRA_PROJECT_KEY"]
JIRA_STORY_KEY = os.environ["JIRA_STORY_KEY"]

_auth = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
HEADERS = {
    "Authorization": f"Basic {_auth}",
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


def fingerprint_label(finding):
    # file:category:snippet, not file:line:category — survives line-number
    # drift across commits. Not scoped to a PR number — the same bug found on
    # a different PR, or regressing later, must resolve to the same tag so it
    # reopens the original ticket instead of creating a duplicate.
    snippet = " ".join(finding.get("code_snippet", "").split())
    key = f"{finding.get('file','')}:{finding.get('category','')}:{snippet}"
    short_hash = hashlib.sha1(key.encode()).hexdigest()[:8]
    return f"secreview-{short_hash}"


def _search(jql, fields, max_results=50):
    # NOTE: /rest/api/3/search was retired (HTTP 410) 2025-08-01; this uses
    # the replacement /rest/api/3/search/jql endpoint.
    issues = []
    next_token = None
    while True:
        params = {"jql": jql, "fields": fields, "maxResults": str(max_results)}
        if next_token:
            params["nextPageToken"] = next_token
        query = urllib.parse.urlencode(params)
        result = jira_request("GET", f"/rest/api/3/search/jql?{query}")
        issues.extend(result.get("issues", []))
        next_token = result.get("nextPageToken")
        if not next_token:
            break
    return issues


def existing_issue(label):
    # Deliberately not filtered to open-only or to any one PR — an issue with
    # a matching fingerprint, whatever its status or origin, is this same finding.
    issues = _search(f'project = "{JIRA_PROJECT_KEY}" AND labels = "{label}"', "key,status", max_results=1)
    if not issues:
        return None
    issue = issues[0]
    is_done = issue["fields"]["status"]["statusCategory"]["key"] == "done"
    return {"key": issue["key"], "is_done": is_done}


def issues_for_pr(pr_number):
    # Every currently-open ticket labeled for this PR — either raised by it
    # originally, or relabeled onto it by reopen_issue() below when a finding
    # from an earlier PR regressed here. Used by the merge-time bulk close.
    jql = (
        f'project = "{JIRA_PROJECT_KEY}" AND parent = "{JIRA_STORY_KEY}" '
        f'AND labels = "security-review" AND labels = "pr-{pr_number}" '
        f'AND statusCategory != Done'
    )
    return _search(jql, "status", max_results=50)


def _comment(key, text):
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
        }
    }
    jira_request("POST", f"/rest/api/3/issue/{key}/comment", payload)


def _add_label(key, label):
    jira_request("PUT", f"/rest/api/3/issue/{key}", {"update": {"labels": [{"add": label}]}})


def close_issue(key, comment_text):
    transitions = jira_request("GET", f"/rest/api/3/issue/{key}/transitions").get("transitions", [])
    # Prefer a transition named exactly "Done" (the standard terminal status),
    # then anything containing "done", then fall back to "close"/"resolve" for
    # workflows that use different terminology for their terminal state.
    target = (
        next((t for t in transitions if (t.get("name") or "").strip().lower() == "done"), None)
        or next((t for t in transitions if "done" in (t.get("name") or "").lower()), None)
        or next((t for t in transitions if any(w in (t.get("name") or "").lower() for w in ("close", "resolve"))), None)
    )
    if not target:
        available = [t.get("name") for t in transitions]
        print(f"::warning::No suitable 'Done' transition found for {key}; leaving status "
              f"as-is. Available transitions: {available}")
        return False
    jira_request("POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": target["id"]}})
    _comment(key, comment_text)
    return True


def reopen_issue(key, pr_context):
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
    _comment(
        key,
        f"Regression: this finding was detected again in PR {pr_context['PR_URL']} "
        f"(#{pr_context['PR_NUMBER']}) by {pr_context['PR_AUTHOR']} on branch "
        f"{pr_context['PR_BRANCH']} @ {pr_context['COMMIT_SHA'][:7]}.",
    )
    # Additive relabel: a finding first raised on PR #90 that regresses on PR
    # #100 needs pr-100's label too, or PR #100's own merge-time bulk close
    # would never find it again (it would still only be labeled pr-90).
    _add_label(key, f"pr-{pr_context['PR_NUMBER']}")


def adf_description(finding, pr_context):
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
            para(f"PR: {pr_context['PR_URL']} (#{pr_context['PR_NUMBER']}) by {pr_context['PR_AUTHOR']} "
                 f"on branch {pr_context['PR_BRANCH']} @ {pr_context['COMMIT_SHA'][:7]}"),
        ],
    }


def create_subtask(finding, label, pr_context):
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "parent": {"key": JIRA_STORY_KEY},
            "issuetype": {"name": "Sub-task"},
            "summary": f"[{finding.get('severity','')}] {finding.get('category','')} in {finding.get('file','')}",
            "description": adf_description(finding, pr_context),
            "labels": ["security-review", f"pr-{pr_context['PR_NUMBER']}", label],
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
              "secrets.jira_project_key and secrets.jira_story_key are actually set.")
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


def sync_findings(findings, severities, pr_context):
    """Create/skip/reopen one Jira sub-task per finding, keyed by fingerprint.
    This is the single shared implementation — the push-time sync and the
    merge-time resync both call this instead of each keeping their own copy."""
    created_keys, reopened_keys, skipped_keys = [], [], []
    for finding in findings:
        severity = (finding.get("severity") or "").upper()
        if severity not in severities:
            continue
        label = fingerprint_label(finding)
        existing = existing_issue(label)
        if existing is None:
            key = create_subtask(finding, label, pr_context)
            print(f"Created {key} for {label}")
            created_keys.append(key)
        elif existing["is_done"]:
            key = existing["key"]
            reopen_issue(key, pr_context)
            print(f"Reopened {key} for {label} (regression)")
            reopened_keys.append(key)
        else:
            print(f"Skipping existing open issue {existing['key']} for {label}")
            skipped_keys.append(existing["key"])
    return {"created": created_keys, "reopened": reopened_keys, "skipped_existing": skipped_keys}
