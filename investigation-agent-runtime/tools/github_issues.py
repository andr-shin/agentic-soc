"""GitHub Issues integration tools — create, comment, list incident issues.
Only loaded when GITHUB_PAT environment variable is set."""
import json
import logging
import os
import urllib.request

from strands import tool

logger = logging.getLogger("incident-agent.github")

GITHUB_PAT = os.environ.get('GITHUB_PAT', '')
GITHUB_REPO = os.environ.get('GITHUB_REPO', '')  # owner/repo format


def _gh_request(method: str, path: str, body: dict = None) -> dict:
    """Make authenticated request to GitHub REST API."""
    url = f"https://api.github.com{path}"
    headers = {
        'Authorization': f'Bearer {GITHUB_PAT}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
    }
    data = json.dumps(body).encode('utf-8') if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return {'error': f"GitHub API error {e.code}: {e.read().decode('utf-8')[:500]}"}
    except Exception as e:
        return {'error': f"GitHub request failed: {str(e)}"}


@tool
def github_create_issue(title: str, body: str, labels: str = "incident") -> dict:
    """Create a GitHub issue for incident tracking.
    Parameters:
      title: Issue title (required)
      body: Issue body in markdown (required)
      labels: Comma-separated labels e.g. 'incident,severity-high' (default: 'incident')
    """
    if not GITHUB_REPO:
        return {'error': 'GITHUB_REPO not configured'}

    try:
        label_list = [l.strip() for l in labels.split(',') if l.strip()]
        result = _gh_request('POST', f'/repos/{GITHUB_REPO}/issues', {
            'title': title,
            'body': body,
            'labels': label_list,
        })

        if 'error' in result:
            return result

        return {
            'issue_number': result.get('number'),
            'url': result.get('html_url'),
            'title': result.get('title'),
            'state': result.get('state'),
        }
    except Exception as e:
        return {'error': str(e)}


@tool
def github_add_comment(issue_number: int, comment: str) -> dict:
    """Add a comment to an existing GitHub issue.
    Parameters:
      issue_number: Issue number (required)
      comment: Comment body in markdown (required)
    """
    if not GITHUB_REPO:
        return {'error': 'GITHUB_REPO not configured'}

    try:
        result = _gh_request('POST', f'/repos/{GITHUB_REPO}/issues/{issue_number}/comments', {
            'body': comment,
        })

        if 'error' in result:
            return result

        return {
            'comment_id': result.get('id'),
            'issue_number': issue_number,
            'url': result.get('html_url'),
        }
    except Exception as e:
        return {'error': str(e)}


@tool
def github_list_issues(state: str = "open", labels: str = "incident", limit: int = 20) -> dict:
    """List GitHub issues for incident tracking.
    Parameters:
      state: Issue state — 'open', 'closed', 'all' (default: 'open')
      labels: Filter by labels, comma-separated (default: 'incident')
      limit: Max issues to return (default: 20)
    """
    if not GITHUB_REPO:
        return {'error': 'GITHUB_REPO not configured'}

    try:
        params = f"state={state}&labels={labels}&per_page={limit}&sort=updated&direction=desc"
        result = _gh_request('GET', f'/repos/{GITHUB_REPO}/issues?{params}')

        if isinstance(result, dict) and 'error' in result:
            return result

        issues = []
        for issue in (result if isinstance(result, list) else [])[:limit]:
            issues.append({
                'number': issue.get('number'),
                'title': issue.get('title', '-')[:100],
                'state': issue.get('state'),
                'labels': [l.get('name') for l in issue.get('labels', [])],
                'created_at': issue.get('created_at'),
                'updated_at': issue.get('updated_at'),
                'comments': issue.get('comments', 0),
                'url': issue.get('html_url'),
            })

        return {'issues': issues, 'count': len(issues), 'state': state}
    except Exception as e:
        return {'error': str(e)}
