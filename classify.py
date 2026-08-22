"""
Subclassifiers for transitions that fire too broadly to report raw.

The lesson from package_identifier_changed, which over-reported by 24x: a
detector count is a hypothesis, not a finding. Every detector that fires more
than a handful of times gets subclassified and audited before its number goes
anywhere near a writeup.

repo_owner_changed fired 192 times and manual sampling showed at least five
distinct phenomena mashed together, ranging from "GitHub org renamed itself
with different capitalisation" (noise) to "org handed the repo to a personal
account" (the actual signal).
"""

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# Strings that indicate an unedited template made it into the live registry.
# Finding these at all is a result: it means the registry verifies NAMESPACE
# ownership but does not validate that the supplied repository URL exists or
# belongs to the publisher.
PLACEHOLDER_PATTERNS = [
    r"your[-_]?github[-_]?username", r"^yourusername$", r"^username$",
    r"^your[-_]?org", r"^example$", r"^example[-_]", r"^todo$", r"^changeme$",
    r"^my[-_]?org$", r"^owner$", r"^placeholder$", r"^user$", r"^test$",
]

# Characters that render near-identically in common UI fonts. Collapsing them
# reveals pairs like Alweather / AIweather (lowercase L versus capital i),
# which is the setup for owner-name squatting.
CONFUSABLES = str.maketrans({
    "l": "1", "i": "1", "I": "1", "|": "1",
    "0": "o", "O": "o",
    "5": "s", "S": "s",
    "2": "z",
})


def forge(url):
    return (urlparse(url or "").hostname or "").lower()


def owner(url):
    parts = [p for p in urlparse(url or "").path.split("/") if p]
    return parts[0] if parts else ""


def norm(s):
    """Case and punctuation insensitive. HSH-Intelligence and hshintelligence
    are the same entity and must not be counted as an ownership change."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def confusable(s):
    return norm(s).translate(CONFUSABLES)


def is_placeholder(o):
    low = (o or "").lower()
    return any(re.search(p, low) for p in PLACEHOLDER_PATTERNS)


def namespace_owner(server_name):
    """The registry verifies namespace ownership at publication. For
    io.github.X/* the verified identity IS the GitHub owner X, so a repository
    URL pointing somewhere else is a divergence between who the registry
    checked and where the code actually lives. That is a purely offline,
    exactly-computable signal and it is the sharpest one available here.

    For reverse-DNS namespaces (com.foo/bar) the verified identity is a domain,
    so the comparison is looser and returns the bare domain label.
    """
    name = server_name or ""
    ns = name.split("/")[0]
    if ns.startswith("io.github."):
        return ns[len("io.github."):], "exact"
    if ns.startswith("io.gitlab."):
        return ns[len("io.gitlab."):], "exact"
    parts = ns.split(".")
    if len(parts) >= 2:
        return parts[-1], "loose"   # com.trendsmcp -> trendsmcp
    return "", "none"


def classify_owner_change(server_name, url_a, url_b):
    """Return (bucket, note). Buckets, most-to-least excludable:

      case_or_punctuation_only  same entity, different formatting. NOISE.
      placeholder_replaced      template string replaced with a real owner.
      forge_changed             moved between GitHub/GitLab/etc.
      homoglyph_confusable      owners differ only by look-alike characters.
      substring_related         one owner contains the other. Likely rebrand.
      both_match_namespace      both carry the verified namespace stem.
      converged_to_namespace    now matches the registry-verified identity.
      diverged_from_namespace   no longer matches it. SIGNAL.
      unrelated                 genuinely different owner. SIGNAL.
    """
    oa, ob = owner(url_a), owner(url_b)
    na, nb = norm(oa), norm(ob)

    if na == nb:
        return "case_or_punctuation_only", "%s -> %s" % (oa, ob)
    if is_placeholder(oa):
        return "placeholder_replaced", "template value %r published live" % oa
    if forge(url_a) != forge(url_b):
        return "forge_changed", "%s -> %s" % (forge(url_a), forge(url_b))
    if confusable(oa) == confusable(ob):
        return "homoglyph_confusable", "%s vs %s collapse to the same glyphs" % (oa, ob)

    ns, mode = namespace_owner(server_name)
    nsn = norm(ns)
    if nsn and mode != "none":
        a_ok = nsn == na or (mode == "loose" and (nsn in na or na in nsn))
        b_ok = nsn == nb or (mode == "loose" and (nsn in nb or nb in nsn))
        if a_ok and b_ok:
            # thehealthai -> healthai-hq. Neither contains the other, but both
            # carry the registry-verified namespace stem, so this is one entity
            # respelling itself rather than a handover.
            return "both_match_namespace", "both carry verified stem %r" % ns
        if b_ok and not a_ok:
            return "converged_to_namespace", "now matches verified namespace %r" % ns
        if a_ok and not b_ok:
            return "diverged_from_namespace", "left verified namespace %r" % ns

    if na in nb or nb in na:
        return "substring_related", "%s -> %s" % (oa, ob)
    return "unrelated", "%s -> %s" % (oa, ob)


# ---------- optional GitHub enrichment ----------

def owner_kind(login, token=None, cache_path="data/github_owner_cache.json"):
    """Resolve a GitHub login to 'User' or 'Organization'.

    Org -> personal is a meaningfully different event from personal -> org: the
    first narrows who is accountable for the code, the second widens it. That
    axis cannot be computed offline, so it needs the GitHub API.

    Cached to disk because 192 transitions means ~380 lookups and the
    unauthenticated limit is 60/hour. With a token it is 5000/hour. Create one
    at github.com/settings/tokens with NO scopes; public data needs none.
    """
    cache_file = Path(cache_path)
    cache = {}
    if cache_file.exists():
        cache = json.loads(cache_file.read_text())
    if login in cache:
        return cache[login]

    req = urllib.request.Request(
        "https://api.github.com/users/" + login,
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": "mcp-registry-longitudinal-study"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            kind = json.loads(r.read()).get("type", "unknown")
    except urllib.error.HTTPError as e:
        kind = "missing" if e.code == 404 else "error_%s" % e.code
    except Exception:
        return "unknown"   # do not cache transient failures

    cache[login] = kind
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cache, indent=0, sort_keys=True))
    return kind