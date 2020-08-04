from collections import namedtuple
from pathlib import Path
import requests
import json
from subprocess import run
from datetime import datetime, timezone
from os import environ


def gh(url, method="GET", data=None, headers=None, token=None):
    headers = dict(
        headers or {}, **{"Accept": "application/vnd.github.antiope-preview+json"}
    )
    if token:
        headers["Authorization"] = f"token {token}"
    return requests.request(method=method, url=url, headers=headers, data=data)


def to_gh_severity(bandit_severity):
    # Maps bandit severity to github annotation_level
    # see: https://docs.github.com/en/rest/reference/checks#create-a-check-run
    bandit_severity = bandit_severity.lower()
    bandit_severity_map = {
        "low": "notice",
        "medium": "warning",
        "high": "failure",
        "undefined": "notice",
    }
    return bandit_severity_map[bandit_severity]


def run_bandit(args, env=None):
    #  Control environment variables passed to bandit.
    out = run(
        ["bandit", "-f", "json"] + args,
        capture_output=True,
        env=env or {"PATH": environ["PATH"]},
    )
    if out.returncode < 2:
        # Everything ok
        return json.loads(out.stdout)
    raise SystemExit(out.stderr)


def bandit_annotation(result):
    try:
        end_line = result["line_range"][-1]
    except (KeyError, IndexError):
        end_line = result["line_number"]

    d = dict(
        path=result["filename"],
        start_line=result["line_number"],
        end_line=end_line,
        annotation_level=to_gh_severity(result["issue_severity"]),
        title="Test: {test_name} id: {test_id}".format(**result),
        message="{issue_text} more info {more_info}".format(**result),
    )

    return d


def bandit_error(error):
    return dict(
        path=error["filename"],
        start_line=1,
        end_line=1,
        annotation_level="failure",
        title="Error processing file (not a python file?)",
        message=error["reason"],
    )


def test_errors():
    results = json.loads(Path("tests/bandit.error.json").read_text())
    errors = [bandit_error(error) for error in results["errors"]]
    assert errors[0]["path"] == "LICENSE"


def bandit_annotations(results):
    return [bandit_annotation(result) for result in results["results"]]


def test_annotations():
    results = json.loads(Path("tests/bandit.json").read_text())
    annotations = bandit_annotations(results)
    assert annotations[0]["path"] == "canary.py"
    assert annotations[0]["start_line"] == 3


def test_run_bandit():
    results = run_bandit(["canary.py"])
    assert "results" in results


def test_run_check():
    results = json.loads(Path("tests/bandit.json").read_text())
    run_check_body = bandit_run_check(results)
    assert run_check_body["conclusion"] == "failure"


def bandit_run_check(results, github_sha=None):
    annotations = bandit_annotations(results)
    errors = [bandit_error(e) for e in results["errors"]]
    conclusion = "success"
    title = "Bandit: no issues found"
    summary = (
        f"""Total statistics: {json.dumps(results['metrics']["_totals"], indent=2)}"""
    )

    if errors or annotations:
        conclusion = "failure"

    return {
        "name": "Bandit comments",
        "head_sha": github_sha,
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
            "annotations": annotations + errors,
        },
    }


if __name__ == "__main__":
    from sys import argv

    results = run_bandit(argv[1:], env={"PATH": environ["PATH"]})
    errors = results["errors"]

    u_patch = "{GITHUB_API_URL}/repos/{GITHUB_REPOSITORY}/commits/{GITHUB_SHA}/check-runs".format(
        **environ
    )

    u_post = "{GITHUB_API_URL}/repos/{GITHUB_REPOSITORY}/check-runs".format(**environ)

    bandit_checks = bandit_run_check(results, environ.get("GITHUB_SHA"))
    res = gh(
        u_post,
        method="POST",
        data=json.dumps(bandit_checks),
        token=environ["GITHUB_TOKEN"],
    )

    print("Workflow status:", res.status_code, res.json(), res.url)

    if res.status_code >= 300:
        raise SystemExit(1)
