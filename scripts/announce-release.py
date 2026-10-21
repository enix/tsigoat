#!/usr/bin/env python3
"""Announces a published release of tsigoat on Slack.

Reads the release event of GitHub Actions, at GITHUB_EVENT_PATH, and posts to
the incoming webhook of SLACK_WEBHOOK the version, the notes of the release in
Slack mrkdwn, and a link to it. With --dry-run, prints the message.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

# The text of a section block holds 3000 characters at most: the notes stop at
# 2900, which leaves room for the mark of the cut.
MAX_NOTES = 2900


def escape(text):
    """Escapes the characters that Slack mrkdwn reads as markup."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def link(url, label):
    """Returns a Slack link to a web address, or the label and the address as
    text: Slack reads <!...>, <@...> and <#...> as mentions of a channel, a
    user or a conversation."""
    if re.match(r"https?://", url):
        return f"<{url}|{label or url}>"
    return f"{label} ({url})" if label else url


def inline(text, repository_url):
    """Turns the inline Markdown of a line into mrkdwn."""
    kept = []

    def keep(markup):
        kept.append(markup)
        return f"\0{len(kept) - 1}\0"

    text = re.sub(r"`[^`]+`", lambda m: keep(escape(m[0])), text)
    text = escape(text)
    text = re.sub(
        r"!?\[([^\]]*)\]\(([^)\s]+)[^)]*\)",
        lambda m: keep(link(m[2], m[1])),
        text,
    )
    # GitHub links the commits, issues and users that the notes name.
    text = re.sub(
        r"\b[0-9a-f]{40}\b",
        lambda m: keep(f"<{repository_url}/commit/{m[0]}|{m[0][:7]}>"),
        text,
    )
    text = re.sub(
        r"(?<![\w&/])#(\d+)\b",
        lambda m: keep(f"<{repository_url}/issues/{m[1]}|#{m[1]}>"),
        text,
    )
    text = re.sub(
        r"(?<![\w.])@([A-Za-z0-9][A-Za-z0-9-]{0,38})\b",
        lambda m: keep(f"<https://github.com/{m[1]}|@{m[1]}>"),
        text,
    )
    text = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: keep(f"*{m[1] or m[2]}*"), text)
    text = re.sub(r"(?<![\w*])\*(?=\S)(.+?)(?<=\S)\*(?![\w*])", r"_\1_", text)
    text = re.sub(r"~~(.+?)~~", r"~\1~", text)
    while "\0" in text:
        text = re.sub(r"\0(\d+)\0", lambda m: kept[int(m[1])], text)
    return text


def mrkdwn(markdown, repository_url):
    """Turns GitHub Markdown, as GoReleaser writes the notes, into mrkdwn."""
    lines = []
    in_code = False
    # inline() marks its conversions with NUL characters.
    for line in markdown.replace("\0", "").replace("\r\n", "\n").split("\n"):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            lines.append("```")
        elif in_code:
            lines.append(escape(line))
        elif heading := re.match(r"\s{0,3}#{1,6}\s+(.*?)[\s#]*$", line):
            lines.append(f"*{inline(heading[1], repository_url)}*")
        elif item := re.match(r"(\s*)[-*+]\s+(.*)", line):
            lines.append(f"{item[1]}• {inline(item[2], repository_url)}")
        elif quote := re.match(r"\s{0,3}>\s?(.*)", line):
            lines.append(f"> {inline(quote[1], repository_url)}")
        else:
            lines.append(inline(line, repository_url))
    return "\n".join(lines).strip()


def truncate(text, limit):
    """Cuts text after its last whole line within limit, and marks the cut."""
    if len(text) <= limit:
        return text
    lines = text[:limit].split("\n")
    return "\n".join(lines[:-1] or lines) + "*[...]*"


def message(release, repository):
    """Returns the Slack message of a release."""
    name, tag = repository["name"], release["tag_name"]
    version = tag.removeprefix("v")
    notes = truncate(mrkdwn(release.get("body") or "", repository["html_url"]), MAX_NOTES)
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"A new version of `{name}` has been released!\nCurrent version is *{version}*",
            },
        }
    ]
    if notes:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": notes}})
    link = f":package: *<{repository['html_url']}|{repository['full_name']}>:*   <{release['html_url']}|{tag}>"
    return {
        "text": f"A new version of {name} has been released!",
        "blocks": blocks,
        "attachments": [
            {
                "color": "#2cbe4e",
                "blocks": [{"type": "context", "elements": [{"type": "mrkdwn", "text": link}]}],
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="print the message rather than post it")
    args = parser.parse_args()

    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
        event = json.load(f)
    payload = message(event["release"], event["repository"])
    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    webhook = os.environ.get("SLACK_WEBHOOK", "")
    if not webhook.startswith("https://"):
        print("::error::SLACK_WEBHOOK must hold the URL of an incoming webhook of the Slack channel.")
        return 1
    request = urllib.request.Request(
        webhook,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
    except urllib.error.HTTPError as e:
        print(f"::error::Slack refused the message: {e.code} {e.read().decode(errors='replace')}")
        return 1
    except urllib.error.URLError as e:
        print(f"::error::Posting to Slack failed: {e.reason}")
        return 1
    print(f"Announced {event['release']['tag_name']} on Slack.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
