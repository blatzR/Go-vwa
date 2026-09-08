import base64, hashlib, json, os, re, urllib.error, urllib.parse, urllib.request

JIRA_BASE_URL = os.environ["JIRA_BASE_URL"].rstrip("/")
JIRA_EMAIL = os.environ["JIRA_EMAIL"]
JIRA_API_TOKEN = os.environ["JIRA_API_TOKEN"]
JIRA_PROJECT_KEY = os.environ["JIRA_PROJECT_KEY"]
JIRA_STORY_KEY = os.environ["JIRA_STORY_KEY"]
CHANGED_FILES = {f.strip() for f in os.environ.get("CHANGED_FILES", "").splitlines() if f.strip()}
PR_URL = os.environ["PR_URL"]
PR_NUMBER = os.environ["PR_NUMBER"]
MERGE_COMMIT_SHA = os.environ.get("MERGE_COMMIT_SHA", "")[:7]

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


def fingerprint(file, category, snippet):
    # Must match fingerprint_label()'s formula exactly (file:category:snippet,
    # not file:line:category) or previously-created issues will never match
    # here and the close logic will silently never fire for them.
    normalized = " ".join(snippet.split())
    key = f"{file}:{category}:{normalized}"
    return f"secreview-{hashlib.sha1(key.encode()).hexdigest()[:8]}"


def fetch_open_security_issues():
    jql = (
        f'project = "{JIRA_PROJECT_KEY}" AND parent = "{JIRA_STORY_KEY}" '
        f'AND labels = "security-review" AND statusCategory != Done'
    )
    issues = []
    next_token = None
    while True:
        params = {"jql": jql, "fields": "description,labels,status", "maxResults": "50"}
        if next_token:
            params["nextPageToken"] = next_token
        query = urllib.parse.urlencode(params)
        result = jira_request("GET", f"/rest/api/3/search/jql?{query}")
        issues.extend(result.get("issues", []))
        next_token = result.get("nextPageToken")
        if not next_token:
            break
    return issues


def extract_file_and_fingerprint(issue):
    fp = next((l for l in issue["fields"]["labels"] if l.startswith("secreview-")), None)
    file_path = None
    for block in issue["fields"]["description"].get("content", []):
        text = "".join(c.get("text", "") for c in block.get("content", []))
        match = re.match(r"File:\s*(\S+)\s+Line:", text)
        if match:
            file_path = match.group(1)
            break
    return file_path, fp


def close_issue(key):
    transitions = jira_request("GET", f"/rest/api/3/issue/{key}/transitions").get("transitions", [])
    target = None
    for t in transitions:
        name = (t.get("name") or "").lower()
        if any(word in name for word in ("done")):
            target = t
            break
    if not target:
        available = [t.get("name") for t in transitions]
        print(f"::warning::No suitable close transition found for {key}; leaving status "
              f"as-is. Available transitions: {available}")
        return False
    jira_request("POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": target["id"]}})
    comment_payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": f"Resolved: no longer detected after {PR_URL} (#{PR_NUMBER}) merged "
                            f"(commit {MERGE_COMMIT_SHA}).",
                }],
            }],
        }
    }
    jira_request("POST", f"/rest/api/3/issue/{key}/comment", comment_payload)
    return True


def main():
    try:
        current_findings = json.load(open("verification-findings.json")).get("findings", [])
    except FileNotFoundError:
        current_findings = []
    current_fingerprints = {
        fingerprint(f.get("file", ""), f.get("category", ""), f.get("code_snippet", ""))
        for f in current_findings
    }

    closed_keys = []
    still_open_keys = []
    out_of_scope_keys = []

    for issue in fetch_open_security_issues():
        key = issue["key"]
        file_path, fp = extract_file_and_fingerprint(issue)
        if file_path is None or file_path not in CHANGED_FILES:
            # This run never looked at that file, so its absence from
            # current_findings proves nothing — leave it alone.
            out_of_scope_keys.append(key)
            continue
        if fp in current_fingerprints:
            still_open_keys.append(key)
            continue
        if close_issue(key):
            closed_keys.append(key)

    print(f"Closed: {closed_keys}")
    print(f"Still open (re-confirmed): {still_open_keys}")
    print(f"Out of scope (file not touched by this PR): {out_of_scope_keys}")

    with open("jira-resolve-summary.json", "w") as f:
        json.dump({"closed": closed_keys, "still_open": still_open_keys}, f, indent=2)


main()
