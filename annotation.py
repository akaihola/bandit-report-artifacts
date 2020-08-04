from os import environ
from base64 import encodebytes
from sys import argv
from pathlib import Path
import requests
import json




def gh(url, method="GET", data=None, headers=None, token=None):
    headers = dict(
        headers or {}, **{"Accept": "application/vnd.github.antiope-preview+json"}
    )
    if token:
        headers["Authorization"] = f"token {token}"
    return requests.request(method=method, url=url, headers=headers, data=data)


def to_gh_severity(bandit_severity):
    if bandit_severity == "LOW":
        return "notice"
    return "warning"


results = json.loads(Path("bandit.json").read_text())
errors = results["errors"]
annotations = [
    dict(
        path=result["filename"],
        start_line=result["line_number"],
        end_line=result["line_number"],
        annotation_level=to_gh_severity(result["issue_severity"]),
        title=result["test_name"],
        message=result["issue_text"],
    )
    for result in results["results"]
]

u_patch = "{GITHUB_API_URL}/repos/{GITHUB_REPOSITORY}/commits/{GITHUB_SHA}/check-runs".format(
    **environ
)

u_post = "{GITHUB_API_URL}/repos/{GITHUB_REPOSITORY}/check-runs".format(
    **environ
)

from datetime import datetime, timezone

#res = gh(u_patch, method="PATCH", data=json.dumps({"annotations": annotations}), token=environ["GITHUB_TOKEN"])
res = gh(u_post, method="POST", data=json.dumps({
    "name": "Bandit comments",
    "head_sha": environ.get('GITHUB_SHA'),
    "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "annotations": annotations,
    "conclusion": "success" if not errors else "failure",
    "output": {
        "title": "Bandit is ok",
        "summary": repr(errors),
        "annotations": annotations,
    }
}), token=environ["GITHUB_TOKEN"])

print("Workflow status:", res.status_code, res.json(), res.url)

if res.status_code >= 300:
    raise SystemExit(1)

results = [
    {
        "code": "40 \n41     p = randint(0, 10)\n42 \n",
        "filename": "swagger_server/controllers/public_controller.py",
        "issue_confidence": "HIGH",
        "issue_severity": "LOW",
        "issue_text": "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        "line_number": 41,
        "line_range": [41],
        "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b311-random",
        "test_id": "B311",
        "test_name": "blacklist",
    },
    {
        "code": '22         self.assert200(response, "Response body is : " + response.data.decode("utf-8"))\n23         assert "x-ratelimit-limit" in response.headers\n24 \n',
        "filename": "swagger_server/test/test_public_controller.py",
        "issue_confidence": "HIGH",
        "issue_severity": "LOW",
        "issue_text": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
        "line_number": 23,
        "line_range": [23],
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html",
        "test_id": "B101",
        "test_name": "assert_used",
    },
]
