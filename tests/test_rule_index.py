"""Tests for the trie-based rule index behind ``Protego.can_fetch``.

The interesting assertion is a differential one: a deliberately independent,
deliberately slow sequential scanner (see :class:`SequentialReference`) parses
the same rules and is compared against Protego on random short rules and URLs.
The index is only allowed to skip rules; it must never change the answer.
"""

from __future__ import annotations

import random
import time

import pytest

from protego import Protego
from protego._utils import _hexescape, _quote_path, _quote_pattern


# Rule kinds used by the reference scanner. They intentionally use local
# constants rather than protego's private ones, so the two implementations
# cannot accidentally agree through a shared constant.
PREFIX = 0
EXACT = 1
WILDCARD = 2


class SequentialReference:
    """Sequential-scan reference for one ``User-agent: *`` group.

    Every rule is stored as the triples Protego builds and matched with a
    plain loop, the first matching rule winning. Its parsing reuses the
    project's percent-encoding normalization (the exact spelling of an
    encoded URL is not what is under test here), but its rule classification
    and its matcher are written from scratch and never import the index or
    the production match loop.
    """

    def __init__(self) -> None:
        self.rules: list[tuple[str, str]] = []

    def _add(self, field: str, raw_pattern: str) -> None:
        # A "$" is always percent-escaped first: only the copy made below may
        # keep a trailing "$" as the end anchor.
        if "$" in raw_pattern:
            escaped = raw_pattern.replace("$", _hexescape("$"))
        else:
            escaped = raw_pattern
        normalized = _quote_pattern(escaped)
        self.rules.append((field, normalized))

        if raw_pattern.endswith("$"):
            anchored = _quote_pattern(raw_pattern[:-1])
            self.rules.append((field, anchored + "$"))

        # The index.html special case: allowing ".../index.html" also allows
        # the directory itself, anchored to its end.
        if field == "allow" and normalized.endswith("/index.html"):
            self.rules.append((field, normalized.removesuffix("index.html") + "$"))

    def allow(self, pattern: str) -> None:
        self._add("allow", pattern)

    def disallow(self, pattern: str) -> None:
        self._add("disallow", pattern)

    @staticmethod
    def _compile(pattern: str) -> tuple[int, object]:
        if "*" in pattern:
            anchored = pattern.endswith("$")
            if anchored:
                pattern = pattern[:-1]
            # Collapse runs of stars, mirroring the documented wildcard rule.
            while "**" in pattern:
                pattern = pattern.replace("**", "*")
            parts = pattern.split("*")
            return WILDCARD, (parts, anchored)
        if pattern.endswith("$"):
            return EXACT, pattern[:-1]
        return PREFIX, pattern

    def _sorted_compiled(self) -> list[tuple[int, object, bool, int]]:
        compiled = [
            (kind, data, field == "disallow", len(pattern))
            for field, pattern in self.rules
            for kind, data in [self._compile(pattern)]
        ]
        # Longest pattern first; at equal length allow beats disallow.
        compiled.sort(key=lambda rule: (rule[3], not rule[2]), reverse=True)
        return compiled

    @staticmethod
    def _matches(kind: int, data: object, url: str) -> bool:
        if kind == PREFIX:
            return url.startswith(data)
        if kind == EXACT:
            return url == data

        parts, anchored = data
        if not url.startswith(parts[0]):
            return False
        pos = len(parts[0])
        for part in parts[1:-1]:
            found = url.find(part, pos)
            if found == -1:
                return False
            pos = found + len(part)
        last = parts[-1]
        if anchored:
            end = len(url) - len(last)
            return end >= pos and url[end:] == last
        return not last or url.find(last, pos) != -1

    def can_fetch(self, url: str) -> bool:
        url = _quote_path(url)
        for kind, data, is_disallow, _priority in self._sorted_compiled():
            if self._matches(kind, data, url):
                return not is_disallow
        return True


def _random_pattern(rng: random.Random) -> str:
    length = rng.randint(0, 6)
    pattern = "".join(rng.choice("/abc*$") for _ in range(length))
    if rng.random() < 0.3:
        pattern = "/" + pattern
    if rng.random() < 0.15:
        pattern += "$"
    return pattern


def _random_url(rng: random.Random) -> str:
    length = rng.randint(0, 10)
    path = "".join(rng.choice("/abcdef?=") for _ in range(length))
    if rng.random() < 0.2:
        path = "index.html"
    return "https://example.test" + path


@pytest.mark.parametrize("seed", range(60))
def test_random_rules_match_the_sequential_reference(seed: int) -> None:
    rng = random.Random(seed)
    reference = SequentialReference()
    lines = ["User-agent: *"]
    for _ in range(rng.randint(1, 40)):
        directive = rng.choice(["allow", "disallow"])
        pattern = _random_pattern(rng)
        lines.append(f"{directive}: {pattern}")
        if pattern:
            getattr(reference, directive)(pattern)

    # Fixed shapes mixed in on purpose: empty first wildcard parts,
    # consecutive stars, an anchored wildcard and the index.html special case.
    for directive, pattern in [
        ("disallow", "*/admin"),
        ("disallow", "/a/**/b"),
        ("disallow", "/x/*/end$"),
        ("allow", "/folder/index.html"),
        ("disallow", "/$"),
    ]:
        lines.append(f"{directive}: {pattern}")
        getattr(reference, directive)(pattern)

    parser = Protego.parse("\n".join(lines))
    for _ in range(120):
        url = _random_url(rng)
        assert parser.can_fetch(url, "*") == reference.can_fetch(url), (
            f"seed={seed} url={url!r} rules={lines!r}"
        )


def _disjoint_prefix_robotstxt(prefix_count: int, wildcard_count: int) -> str:
    lines = ["User-agent: *"]
    for index in range(prefix_count):
        # Each prefix lives under its own directory, so a URL matches at most
        # one of them and no two share more than the root of the trie.
        lines.append(f"Disallow: /p{index:06d}/")
    for index in range(wildcard_count):
        # Wildcards interleave with the prefixes and, being long, outrank
        # every prefix when they match.
        lines.append(f"Allow: /w{index:06d}/*/leaf$")
    return "\n".join(lines)


@pytest.mark.parametrize("prefix_count", [100, 1_000, 5_000])
def test_check_count_is_sublinear_for_unseen_urls(prefix_count: int) -> None:
    robotstxt = _disjoint_prefix_robotstxt(prefix_count, wildcard_count=4)
    parser = Protego.parse(robotstxt)
    rule_set = parser._get_matching_rule_set("*")
    assert rule_set is not None

    unseen_url = "https://example.test/zzz/unrelated/path"
    matching_url = f"https://example.test/p{prefix_count - 1:06d}/page"

    allowed_unseen, checks_unseen = rule_set.can_fetch_with_check_count(unseen_url)
    allowed_match, checks_match = rule_set.can_fetch_with_check_count(matching_url)

    assert allowed_unseen is True
    assert allowed_match is False
    # A fresh, never-seen-before URL must benefit too: the number of checks is
    # bounded by the URL walk and the handful of wildcard buckets rather than
    # by the number of rules. Ten is a loose bound far below any prefix count.
    assert checks_unseen <= 10
    assert checks_match <= 10
    assert checks_unseen < prefix_count
    assert checks_match < prefix_count


def test_check_count_stays_flat_as_prefixes_grow() -> None:
    measured: list[tuple[int, int]] = []
    for prefix_count in (250, 1_000, 4_000):
        parser = Protego.parse(_disjoint_prefix_robotstxt(prefix_count, 2))
        rule_set = parser._get_matching_rule_set("*")
        assert rule_set is not None
        _allowed, checks = rule_set.can_fetch_with_check_count(
            "https://example.test/brand/new/url"
        )
        measured.append((prefix_count, checks))

    smallest = measured[0][1]
    largest = measured[-1][1]
    # Multiplying the rule count by 16 must not multiply the check count.
    assert largest <= smallest + 2


def test_higher_priority_wildcard_is_not_skipped_by_prefix_index() -> None:
    # The long wildcard allow must win over the short disallow prefix even
    # though the prefix index finds the prefix rule first.
    robotstxt = (
        "User-agent: *\n"
        "Disallow: /\n"
        "Allow: /assets/*/logo$\n"
    )
    parser = Protego.parse(robotstxt)
    rule_set = parser._get_matching_rule_set("*")
    assert rule_set is not None
    assert parser.can_fetch("https://example.test/assets/brand/logo", "*")
    assert not parser.can_fetch("https://example.test/assets/brand/other", "*")

    _allowed, checks = rule_set.can_fetch_with_check_count(
        "https://example.test/assets/brand/logo"
    )
    # Both the root prefix and the wildcard are arbitrated together.
    assert checks >= 2


def test_exact_prefix_and_wildcard_arbitrate_together() -> None:
    robotstxt = (
        "User-agent: *\n"
        "Disallow: /account/contact$\n"
        "Allow: /account\n"
        "Disallow: /account/*/secret\n"
    )
    parser = Protego.parse(robotstxt)
    cases = {
        "https://example.test/account/contact": False,
        "https://example.test/account": True,
        "https://example.test/account/x/secret": False,
        "https://example.test/account/public": True,
    }
    for url, expected in cases.items():
        assert parser.can_fetch(url, "*") is expected


def test_index_is_built_lazily_and_reused_per_group() -> None:
    parser = Protego.parse("User-agent: *\nDisallow: /a\nDisallow: /b\n")
    rule_set = parser._get_matching_rule_set("*")
    assert rule_set is not None
    assert rule_set._index is None

    parser.can_fetch("https://example.test/a", "fresh-agent")
    first_index = rule_set._index
    assert first_index is not None

    # Another crawler name mapping to the same group reuses the very same
    # index instead of rebuilding it.
    parser.can_fetch("https://example.test/b", "another-agent")
    assert rule_set._index is first_index


def test_indexes_of_different_groups_are_isolated() -> None:
    robotstxt = (
        "User-agent: goodbot\n"
        "Allow: /\n"
        "Disallow: /private\n"
        "User-agent: badbot\n"
        "Disallow: /\n"
        "User-agent: *\n"
        "Disallow: /shared\n"
    )
    parser = Protego.parse(robotstxt)

    good = parser._get_matching_rule_set("goodbot")
    bad = parser._get_matching_rule_set("badbot")
    star = parser._get_matching_rule_set("nobodybot")
    assert good is not bad and bad is not star and good is not star

    parser.can_fetch("https://example.test/private", "goodbot")
    parser.can_fetch("https://example.test/private", "badbot")
    parser.can_fetch("https://example.test/private", "nobodybot")

    # Each group owns a distinct index over its own rules.
    assert good._index is not None
    assert bad._index is not None
    assert star._index is not None
    assert good._index is not bad._index
    assert bad._index is not star._index

    # Rules never leak across crawlers.
    assert parser.can_fetch("https://example.test/anything", "goodbot")
    assert not parser.can_fetch("https://example.test/anything", "badbot")
    assert parser.can_fetch("https://example.test/anything", "nobodybot")
    assert not parser.can_fetch("https://example.test/shared", "nobodybot")


def test_empty_prefix_and_consecutive_stars() -> None:
    robotstxt = (
        "User-agent: *\n"
        "Disallow: */admin\n"
        "Disallow: /a/**/b\n"
        "Allow: /\n"
    )
    parser = Protego.parse(robotstxt)
    reference = SequentialReference()
    reference.disallow("*/admin")
    reference.disallow("/a/**/b")
    reference.allow("/")
    for url in [
        "https://example.test/admin",
        "https://example.test/x/admin",
        "https://example.test/a/x/b",
        "https://example.test/a//b",
        "https://example.test/a/b",
        "https://example.test/other",
    ]:
        assert parser.can_fetch(url, "*") == reference.can_fetch(url)


def test_wall_clock_is_recorded_without_a_machine_threshold() -> None:
    # Wall-clock numbers are only supporting evidence: they vary with the
    # machine, so this test never asserts on milliseconds. The enforceable
    # claim lives in the check-count tests above.
    parser = Protego.parse(_disjoint_prefix_robotstxt(4_000, 4))
    rule_set = parser._get_matching_rule_set("*")
    assert rule_set is not None

    started = time.perf_counter()
    rule_set.can_fetch_with_check_count("https://example.test/first/query")
    first_query_seconds = time.perf_counter() - started

    started = time.perf_counter()
    for index in range(4_000):
        rule_set.can_fetch(f"https://example.test/p{index:06d}/page")
    hot_seconds = time.perf_counter() - started

    assert first_query_seconds >= 0
    assert hot_seconds >= 0
