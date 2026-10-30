"""Daily watcher for Voice for Voiceless's public indicator lists. Python standard library only.

1. Citizen Lab: reads the research feed, and from each new report drafts *candidates*: the
   values written in Citizen Lab's "defanged" style (example[.]com, 192.0.2[.]1, hxxps://...).
   They are NOT used until a person approves them (owner decision 2026-10-29, after a test on
   real reports showed automatic reading would flag news sites and certificate labels and miss
   real servers). The daily job puts the candidates, each with the sentence it came from, into
   a pull request that adds them to lists/citizenlab-reviewed.tsv; the reviewer deletes wrong
   lines and merges. Every installed app then picks them up at its next list update.
2. Amnesty: lists AmnestyTech/investigations and adds every machine-readable list that MVT's
   index doesn't already include.
3. Writes sources.json, which every installed app reads to learn which lists to download.

Run: python3 watcher/watch.py   (writes lists/ and sources.json; prints what is new)
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_RAW = "https://raw.githubusercontent.com/qubix-wk/voice-for-voiceless-indicators/main/"
FEED = "https://citizenlab.ca/feed/?post_type=research"
MVT_INDEX = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
AMNESTY_TREE = "https://api.github.com/repos/AmnestyTech/investigations/git/trees/master?recursive=1"
AMNESTY_RAW = "https://raw.githubusercontent.com/AmnestyTech/investigations/master/"
UA = {"User-Agent": "VoiceForVoiceless-watcher (github.com/qubix-wk/voice-for-voiceless-indicators)"}

# Defanged forms Citizen Lab uses: dots as [.], and hxxp(s) for links. Any value with at least
# one "[.]" counts, including short names like mtrtb[.]com.
_DEFANGED = re.compile(
    r"(?i)(?:hxxps?://)?[a-z0-9_-]+(?:(?:\[\.\]|\.)[a-z0-9_-]+)+(?:/[^\s<>\"')\]]*)?")
# Words around a value that mean it isn't something a device contacts.
_NOT_CONTACT = re.compile(r"(?i)certificate|common name|\bCN=|subject|issuer|fingerprint|"
                          r"censys|redact|e\.g\.|for example|such as")
_SHARED = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "google.com", "apple.com", "icloud.com",
           "microsoft.com", "github.com", "t.me", "telegram.org", "whatsapp.com", "facebook.com",
           "twitter.com", "x.com", "youtube.com", "amazonaws.com", "cloudfront.net"}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read(30 * 1024 * 1024)


def text_of(page: str) -> str:
    page = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", page)
    page = re.sub(r"(?i)<br\s*/?>|</(p|li|tr|td|th|h\d|div)>", "\n", page)
    return re.sub(r"[ \t]+", " ", html.unescape(re.sub(r"<[^>]+>", " ", page)))


def refang(value: str) -> str:
    v = value.replace("[.]", ".").replace("[:]", ":")
    v = re.sub(r"(?i)^hxxp", "http", v)
    v = v.rstrip(".,;:)").lower()
    return v[:-1] if v.endswith("/") and v.count("/") in (1, 3) else v  # "host/" -> "host"


def _ok_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global  # skips private, example and reserved addresses


def extract(text: str) -> list[tuple[str, str, str]]:
    """[(candidate, the sentence it came from, warning for the reviewer)] from a report.
    Generous on purpose: a person reviews every candidate, so the warning flags the doubtful
    ones instead of dropping them."""
    out: dict[str, tuple[str, str]] = {}
    for m in _DEFANGED.finditer(text):
        raw = m.group(0)
        if "[.]" not in raw:
            continue  # not defanged: a mention, not an indicator
        if re.search(r"(?i)x{2,}|\*", raw):
            continue  # redacted
        value = refang(raw)
        host = re.sub(r"^https?://", "", value).split("/")[0].split(":")[0]
        if re.fullmatch(r"[\d.]+", host):
            if not _ok_ip(host):
                continue
        elif host.endswith((".example", ".test", ".invalid")) or "." not in host:
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        sentence = re.sub(r"\s+", " ", text[line_start:line_end if line_end > 0 else None])
        context = text[max(0, m.start() - 300):m.end() + 100]
        warn = []
        if _NOT_CONTACT.search(context):
            warn.append("near words like 'certificate'/'fingerprint': may be a label, not an "
                        "address devices contact")
        if host in _SHARED or any(host.endswith("." + x) for x in _SHARED):
            warn.append("shared service: only the exact link may be malicious")
        if re.search(r"(?i)\bvisit(ed|ing)?\b|\bwebsite\b|\bsite\b", context):
            warn.append("near 'visit'/'website': may be an ordinary site where an ad appeared")
        if "?" in value or re.search(r"(?i)test", value):
            warn.append("looks like an example or test address")
        out.setdefault(value, (sentence.strip()[:240], "; ".join(warn)))
    return sorted((v, s, w) for v, (s, w) in out.items())


def citizenlab(state: dict) -> list[dict]:
    """New reports' indicators (also appended to lists/citizenlab-auto.tsv)."""
    feed = fetch(FEED).decode("utf-8", "replace")
    new_rows = []
    for item in re.findall(r"(?s)<item>(.*?)</item>", feed):
        link = re.search(r"<link>(.*?)</link>", item)
        if not link:
            continue
        url = link.group(1).strip()
        if url in state["seen"]:
            continue
        title = html.unescape(re.sub(r"<!\[CDATA\[|\]\]>", "",
                                     re.search(r"(?s)<title>(.*?)</title>", item).group(1)))
        date = re.search(r"<pubDate>(.*?)</pubDate>", item)
        when = datetime.strptime(date.group(1)[:16], "%a, %d %b %Y").date().isoformat() \
            if date else ""
        try:
            found = extract(text_of(fetch(url).decode("utf-8", "replace")))
        except OSError as e:
            print(f"skipped for now ({type(e).__name__}): {url}", file=sys.stderr)
            continue  # tried again tomorrow
        state["seen"].append(url)
        for value, sentence, warn in found:
            new_rows.append({"value": value, "report": title.strip(), "date": when, "url": url,
                             "sentence": sentence, "warn": warn})
    return new_rows


def amnesty_sources(mvt_paths: set[str]) -> list[dict]:
    tree = json.loads(fetch(AMNESTY_TREE))
    out = []
    for node in tree.get("tree", []):
        path = node.get("path", "")
        if node.get("type") != "blob" or f"AmnestyTech/investigations/{path}" in mvt_paths:
            continue
        name = path.rsplit("/", 1)[-1].lower()
        fmt = ("stix2" if name.endswith(".stix2") else
               "domains-txt" if name in ("domains.txt",) else
               "csv-domain-ip" if name == "indicators.csv" else None)
        if fmt:
            folder = path.split("/")[0]
            day, _, topic = folder.partition("_")
            out.append({"name": f"Amnesty International investigation: {folder}",
                        "url": AMNESTY_RAW + path, "format": fmt,
                        "family": f"Amnesty investigation {day} ({topic.replace('_', ' ')})",
                        "category": "targeted"})
    return out


def mvt_paths() -> set[str]:
    text = fetch(MVT_INDEX).decode("utf-8", "replace")
    owners = re.findall(r"owner:\s*(\S+)", text)
    repos = re.findall(r"repo:\s*(\S+)", text)
    paths = re.findall(r"path:\s*(\S+)", text)
    return {f"{o}/{r}/{p}" for o, r, p in zip(owners, repos, paths, strict=False)}


def _review_text(added: list[dict]) -> str:
    if not added:
        return ""
    out = ["New candidate indicators from Citizen Lab reports. **Nothing here is used until this "
           "is merged.** For each line in `lists/citizenlab-reviewed.tsv`, keep it only if the "
           "report says devices contact it (a spyware server, an infection link, a spyware "
           "file); delete labels, ordinary websites, examples and the reporters' own tools. "
           "Change `strong` to `lead` for anything that should only be 'worth a look'.\n"]
    for r in added:
        out.append(f"- [ ] `{r['value']}` — [{r['report']}]({r['url']}) ({r['date']})"
                   + (f"\n  - ⚠️ {r['warn']}" if r["warn"] else "")
                   + f"\n  - > {r['sentence']}\n")
    return "\n".join(out)


def main() -> int:
    state_path = ROOT / "watcher" / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"seen": []}
    rows = citizenlab(state)
    reviewed = ROOT / "lists" / "citizenlab-reviewed.tsv"
    existing = {line.split("\t")[0] for line in reviewed.read_text().splitlines()
                if line and not line.startswith("#")}
    withdrawn = {line.split("\t")[0] for line in
                 (ROOT / "lists" / "withdrawals.tsv").read_text().splitlines()
                 if line and not line.startswith("#")}
    added = [r for r in rows if r["value"] not in existing and r["value"] not in withdrawn]
    if added and "--propose" in sys.argv:  # the daily job: candidates go into a pull request
        with reviewed.open("a") as f:
            for r in added:
                f.write(f"{r['value']}\tstrong\t{r['date']}: {r['report']} {r['url']}\n")
    sources = [
        {"name": "Citizen Lab reports (reviewed)", "url": REPO_RAW +
         "lists/citizenlab-reviewed.tsv", "format": "curated-tsv",
         "family": "Citizen Lab report", "category": "mercenary"},
        {"name": "Paragon Graphite (hand-copied from Citizen Lab, 2025)", "url": REPO_RAW +
         "lists/paragon-graphite-citizenlab.tsv", "format": "curated-tsv",
         "family": "Paragon Graphite", "category": "mercenary"},
        {"name": "Withdrawn indicators", "url": REPO_RAW + "lists/withdrawals.tsv",
         "format": "withdrawals-tsv", "category": "withdrawals"},
    ]
    try:
        sources += amnesty_sources(mvt_paths())
    except OSError as e:
        print(f"Amnesty listing skipped ({type(e).__name__})", file=sys.stderr)
        old = json.loads((ROOT / "sources.json").read_text()) if (ROOT / "sources.json").exists() \
            else {"sources": []}
        sources += [s for s in old["sources"] if s["name"].startswith("Amnesty")]
    (ROOT / "sources.json").write_text(json.dumps(
        {"updated": datetime.now(UTC).isoformat(timespec="seconds"), "sources": sources},
        indent=1) + "\n")
    state["seen"] = state["seen"][-500:]
    state_path.write_text(json.dumps(state, indent=1) + "\n")
    (ROOT / "watcher" / "new.md").write_text(_review_text(added))
    print(f"{len(added)} candidate(s) from Citizen Lab; {len(sources)} sources listed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
