"""Compare two robots.txt policies for the same user agent.

The comparison is performed through :meth:`Protego.can_fetch`, so that agent
group selection, percent-encoding normalization and rule precedence are handled
exactly as for a live fetch decision. Paths are sampled from the patterns the
two policies actually contain rather than guessed at random; every reported
witness is re-checked with ``can_fetch`` on both sides before it is returned.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from ._protego import Protego
    from ._ruleset import _RuleSet
    from ._urlpattern import _URLPattern


class ChangeKind(str, Enum):
    """How the fetch decisions of two policies relate to each other."""

    EQUIVALENT = "equivalent"
    STRICTER = "stricter"
    LOOSER = "looser"
    MIXED = "mixed"
    UNKNOWN = "unknown"


# Filler text used to instantiate the gaps described by wildcard patterns.
_FILLERS = ("", "x", "0", "-", "_", "a/b")

# Paths probed in addition to the ones derived from patterns, so that a
# policy which blocks everything is not mistaken for an empty one.
_BASELINES = ("/", "/robots-witness", "/index.html")


class ComparisonResult(NamedTuple):
    """Outcome of comparing two policies for one user agent.

    ``kind`` classifies the relation between the decisions. The two witness
    lists contain full URLs on which the decisions differ: ``newly_blocked``
    used to be fetchable and is blocked now, ``newly_allowed`` used to be
    blocked and is fetchable now. Every witness is re-checked with
    :meth:`Protego.can_fetch` on both policies. ``reason`` explains the result
    when ``kind`` is :data:`ChangeKind.UNKNOWN`, and is ``None`` otherwise.
    """

    kind: ChangeKind
    newly_blocked: tuple[str, ...]
    newly_allowed: tuple[str, ...]
    budget: int
    checked: int
    reason: str | None


def _matched_rule_set(parser: Protego, user_agent: str) -> _RuleSet | None:
    """Return the rule set that would answer a can_fetch query."""
    return parser._get_matching_rule_set(user_agent)


def _pattern_paths(pattern: _URLPattern) -> tuple[str, ...]:
    """Build concrete paths that exercise every shape of a pattern.

    Wildcard gaps are filled with several values, and the region before and
    after a trailing anchor is probed separately so that prefix and exact
    semantics do not hide each other.
    """
    text = pattern._pattern
    anchored = text.endswith("$")
    if anchored:
        text = text[:-1]

    parts = text.split("*") if "*" in text else [text]
    expansions: list[str] = []

    def expand(remaining: list[str], built: str) -> None:
        if not remaining:
            expansions.append(built)
            return
        head, *tail = remaining
        if tail:
            for filler in _FILLERS:
                expand(tail, built + head + filler)
        else:
            expand(tail, built + head)

    expand(parts, "")

    paths: list[str] = []
    for expansion in expansions:
        if expansion.startswith("/"):
            paths.append(expansion)
        else:
            # A wildcard before the first "/" can consume the leading part,
            # and the rest of the URL then continues from the root.
            paths.append("/" + expansion)
            paths.append("/x" + expansion)

    # Probe a longer URL built from every expansion: an anchored pattern must
    # stop matching there, an unanchored one must keep matching.
    base = paths
    paths = [*base, *(path + "x" for path in base)]
    if not anchored:
        paths.extend([path + "/x" for path in base])
        if text.endswith("/"):
            paths.append(text + "index.html")

    # Rules match paths from the root; expansions without it were handled
    # above, so only root-relative paths are left.
    return tuple(dict.fromkeys(path for path in paths if path.startswith("/")))


def _candidate_paths(parsers: tuple[Protego, Protego], user_agent: str) -> list[str]:
    """Collect the paths to probe from the patterns of both policies.

    Probe order follows how likely a path is to reveal a difference: baselines
    first, then paths whose pattern exists in only one policy, then paths whose
    pattern switched between allow and disallow, then everything else. A tight
    evaluation budget therefore still finds the most probable witnesses first.
    """
    fields: list[dict[str, set[str]]] = [{}, {}]
    paths: list[dict[str, list[str]]] = [{}, {}]
    for index, parser in enumerate(parsers):
        rule_set = _matched_rule_set(parser, user_agent)
        if rule_set is None:
            continue
        rule_set._build_index()
        for rule in rule_set._rules:
            text = rule.value._pattern
            fields[index].setdefault(text, set()).add(rule.field)
            paths[index].setdefault(text, []).extend(_pattern_paths(rule.value))

    first, second = paths[0], paths[1]
    unique = [path for text in first if text not in second for path in first[text]]
    unique += [path for text in second if text not in first for path in second[text]]
    changed = [
        path
        for text in first
        if text in second and fields[0][text] != fields[1][text]
        for path in [*first[text], *second[text]]
    ]
    shared = [
        path
        for text in first
        if text in second and fields[0][text] == fields[1][text]
        for path in first[text]
    ]
    return list(dict.fromkeys([*_BASELINES, *unique, *changed, *shared]))


def _to_url(path: str) -> str:
    """Turn a normalized path into a full URL suitable for can_fetch."""
    if "://" in path:
        return path
    return f"http://robotstxt-witness.invalid{path}"


def _verified(
    old: Protego,
    new: Protego,
    user_agent: str,
    url: str,
    expect_new_allows: bool,
) -> bool:
    """Re-check a witness with can_fetch and confirm the decision differs."""
    old_allows = old.can_fetch(url, user_agent)
    new_allows = new.can_fetch(url, user_agent)
    return new_allows == expect_new_allows and old_allows != new_allows


def compare_policies(
    old: Protego,
    new: Protego,
    user_agent: str,
    *,
    budget: int = 2000,
) -> ComparisonResult:
    """Compare two robots.txt policies for the given user agent.

    Both policies are queried through :meth:`Protego.can_fetch`, so the same
    agent group selection, percent-encoding and rule precedence apply as for a
    real fetch. At most ``budget`` distinct URLs are evaluated; if the budget
    runs out before the sampled space is exhausted, the result is
    :data:`ChangeKind.UNKNOWN` with an explanatory reason rather than a
    classification based on partial evidence. Finding no differing witness is
    only reported as :data:`ChangeKind.EQUIVALENT` once every candidate has
    been evaluated.
    """
    if budget < 1:
        raise ValueError("budget must be a positive integer")

    candidates = _candidate_paths((old, new), user_agent)
    checked = 0
    blocked: list[str] = []
    allowed: list[str] = []

    exhausted = False
    for path in candidates:
        if checked >= budget:
            exhausted = True
            break

        url = _to_url(path)
        old_allows = old.can_fetch(url, user_agent)
        new_allows = new.can_fetch(url, user_agent)
        checked += 1

        if old_allows == new_allows:
            continue
        if new_allows:
            allowed.append(url)
        else:
            blocked.append(url)

    # Every witness is independently re-checked before being reported, so a
    # bug in the sampling loop can never return an unverifiable witness.
    newly_allowed = tuple(
        url
        for url in dict.fromkeys(allowed)
        if _verified(old, new, user_agent, url, expect_new_allows=True)
    )
    newly_blocked = tuple(
        url
        for url in dict.fromkeys(blocked)
        if _verified(old, new, user_agent, url, expect_new_allows=False)
    )

    if exhausted:
        return ComparisonResult(
            kind=ChangeKind.UNKNOWN,
            newly_blocked=newly_blocked,
            newly_allowed=newly_allowed,
            budget=budget,
            checked=checked,
            reason=(
                f"budget of {budget} URL evaluations exhausted with "
                f"{len(candidates) - checked} candidates left untested"
            ),
        )

    if not newly_blocked and not newly_allowed:
        kind = ChangeKind.EQUIVALENT
        reason = None
    elif newly_blocked and newly_allowed:
        kind = ChangeKind.MIXED
        reason = None
    elif newly_blocked:
        kind = ChangeKind.STRICTER
        reason = None
    else:
        kind = ChangeKind.LOOSER
        reason = None

    return ComparisonResult(
        kind=kind,
        newly_blocked=tuple(newly_blocked),
        newly_allowed=tuple(newly_allowed),
        budget=budget,
        checked=checked,
        reason=reason,
    )
