import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jira_common as jc

SYNC_SEVERITIES = {s.strip().upper() for s in os.environ.get("SYNC_SEVERITY", "CRITICAL,HIGH,MEDIUM").split(",")}

PR_NUMBER = os.environ["PR_NUMBER"]
pr_context = {
    "PR_NUMBER": PR_NUMBER,
    "PR_URL": os.environ["PR_URL"],
    "PR_AUTHOR": os.environ["PR_AUTHOR"],
    "PR_BRANCH": os.environ["PR_BRANCH"],
    "COMMIT_SHA": os.environ.get("MERGE_COMMIT_SHA", ""),
}


def main():
    jc.validate_permissions()
    jc.validate_story()

    # Step 1: close every open ticket associated with this PR, unconditionally
    # — no attempt to check whether each one is actually still present. That
    # check happens in step 2 instead, via the exact same fingerprint lookup
    # the push-time sync already uses: anything still genuinely there gets
    # reopened a moment later (same ticket key, not a new one), so this is a
    # transient status flip for persisting findings, not a loss of history.
    # Anything that doesn't come back is the real "resolved by this merge" set.
    to_close = jc.issues_for_pr(PR_NUMBER)
    closed_keys = []
    for issue in to_close:
        key = issue["key"]
        if jc.close_issue(
            key,
            f"Marking Done for re-verification: {pr_context['PR_URL']} (#{PR_NUMBER}) just merged "
            f"(commit {pr_context['COMMIT_SHA'][:7]}). Will reopen automatically if still detected.",
        ):
            closed_keys.append(key)

    # Step 2: re-run the same create/reopen/skip logic the push-time sync uses,
    # against the fresh post-merge scan. A finding that's genuinely gone simply
    # isn't in verification-findings.json, so nothing reopens its ticket and
    # the close from step 1 sticks.
    try:
        current_findings = json.load(open("verification-findings.json")).get("findings", [])
    except FileNotFoundError:
        current_findings = []

    result = jc.sync_findings(current_findings, SYNC_SEVERITIES, pr_context)

    resolved_keys = [k for k in closed_keys if k not in result["reopened"]]

    print(f"Marked Done (resolved): {resolved_keys}")
    print(f"Reopened (still present after merge): {result['reopened']}")
    print(f"Created (new since merge): {result['created']}")

    with open("jira-resolve-summary.json", "w") as f:
        json.dump(
            {
                "closed": resolved_keys,
                "reopened": result["reopened"],
                "created": result["created"],
            },
            f,
            indent=2,
        )


main()
