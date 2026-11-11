import random
from urllib.parse import quote, urlsplit

import pytest

from protego import ChangeKind, ComparisonResult, Protego
from protego._compare import _candidate_paths, _to_url


def _assert_verified(
    result: ComparisonResult, old: Protego, new: Protego, ua: str
) -> None:
    """Every witness must reproduce through real can_fetch on both policies."""
    for url in result.newly_blocked:
        assert old.can_fetch(url, ua)
        assert not new.can_fetch(url, ua)
    for url in result.newly_allowed:
        assert not old.can_fetch(url, ua)
        assert new.can_fetch(url, ua)


class TestCompare:
    def test_equivalent_policies_with_different_rule_text(self):
        old = Protego.parse("User-agent: *\nDisallow: /a\nDisallow: /b\n")
        new = Protego.parse("User-agent: *\nDisallow: /b\nDisallow: /a\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.EQUIVALENT
        assert result.newly_blocked == ()
        assert result.newly_allowed == ()
        assert result.reason is None
        assert result.checked > 0

    def test_equivalent_when_neither_policy_matches_the_agent(self):
        old = Protego.parse("User-agent: other\nDisallow: /\n")
        new = Protego.parse("User-agent: other\nDisallow: /x\n")
        result = old.compare(new, "unlisted-bot")
        assert result.kind is ChangeKind.EQUIVALENT
        assert result.checked > 0

    def test_shadowed_disallow_unmasked_when_allow_is_removed(self):
        # The high-priority allow hides the disallow under length-based
        # precedence; removing it must surface real blocked witnesses.
        old = Protego.parse(
            "User-agent: *\nAllow: /public/x\nDisallow: /public/\n"
        )
        new = Protego.parse("User-agent: *\nDisallow: /public/\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.STRICTER
        assert result.newly_allowed == ()
        assert any(url.endswith("/public/x") for url in result.newly_blocked)
        _assert_verified(result, old, new, "foobot")

    def test_shadowing_makes_a_policy_looser(self):
        old = Protego.parse("User-agent: *\nDisallow: /public/\n")
        new = Protego.parse(
            "User-agent: *\nAllow: /public/x\nDisallow: /public/\n"
        )
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.LOOSER
        assert result.newly_blocked == ()
        assert any(url.endswith("/public/x") for url in result.newly_allowed)
        _assert_verified(result, old, new, "foobot")

    def test_same_prefix_wildcard_crossing_is_mixed(self):
        old = Protego.parse("User-agent: *\nDisallow: /app/*.php\n")
        new = Protego.parse("User-agent: *\nDisallow: /app/*.inc\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.MIXED
        assert any(url.endswith(".php") for url in result.newly_allowed)
        assert any(url.endswith(".inc") for url in result.newly_blocked)
        _assert_verified(result, old, new, "foobot")

    def test_trailing_anchor_tightens_a_prefix_into_an_exact_match(self):
        old = Protego.parse("User-agent: *\nDisallow: /tmp\n")
        new = Protego.parse("User-agent: *\nDisallow: /tmp$\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.LOOSER
        witness = "http://robotstxt-witness.invalid/tmpx"
        assert witness in result.newly_allowed
        assert old.can_fetch(witness, "foobot") is False
        assert new.can_fetch(witness, "foobot") is True
        # The anchored URL itself stays blocked in both policies.
        assert old.can_fetch("http://robotstxt-witness.invalid/tmp", "foobot") is False
        assert new.can_fetch("http://robotstxt-witness.invalid/tmp", "foobot") is False
        _assert_verified(result, old, new, "foobot")

    def test_unicode_paths_produce_verified_witnesses(self):
        old = Protego.parse("User-agent: *\nDisallow: /café/\n")
        new = Protego.parse(
            "User-agent: *\nDisallow: /café/\nDisallow: /日本/\n"
        )
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.STRICTER
        assert result.newly_allowed == ()
        # Witnesses are percent-encoded, and the same decision holds when the
        # Unicode path is supplied percent-encoded by hand.
        for url in result.newly_blocked:
            assert "/%E6%97%A5%E6%9C%AC/" in url
            parts = urlsplit(url)
            encoded = parts._replace(path=quote(parts.path, safe="/%")).geturl()
            assert old.can_fetch(encoded, "foobot")
            assert not new.can_fetch(encoded, "foobot")
        _assert_verified(result, old, new, "foobot")

    def test_agent_group_selection_matches_can_fetch_scoring(self):
        old = Protego.parse(
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nAllow: /\n"
        )
        new = Protego.parse(
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nDisallow: /\n"
        )
        result = old.compare(new, "FooBot/2.0 (compatible)")
        assert result.kind is ChangeKind.STRICTER
        # The wildcard group alone would already block these URLs, so the
        # witnesses prove the comparison used the more specific group.
        assert any(url.endswith("/") for url in result.newly_blocked)
        _assert_verified(result, old, new, "FooBot/2.0 (compatible)")

    def test_adding_a_specific_group_loosens_a_wildcard_block(self):
        old = Protego.parse("User-agent: *\nDisallow: /\n")
        new = Protego.parse(
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nAllow: /\n"
        )
        result = old.compare(new, "FooBot")
        assert result.kind is ChangeKind.LOOSER
        assert result.newly_blocked == ()
        assert result.newly_allowed
        _assert_verified(result, old, new, "FooBot")

    def test_budget_exhaustion_returns_unknown_with_reason(self):
        old = Protego.parse("User-agent: *\nDisallow: /\n")
        new = Protego.parse("User-agent: *\nAllow: /x\nDisallow: /\n")
        result = old.compare(new, "foobot", budget=2)
        assert result.kind is ChangeKind.UNKNOWN
        assert result.checked == 2
        assert result.reason is not None
        assert "budget" in result.reason
        assert "untested" in result.reason

    def test_no_witness_is_not_claimed_equivalent_under_a_tiny_budget(self):
        old = Protego.parse("User-agent: *\nDisallow: /\n")
        new = Protego.parse("User-agent: *\nAllow: /x\nDisallow: /\n")
        result = old.compare(new, "foobot", budget=1)
        assert result.kind is ChangeKind.UNKNOWN
        assert result.kind is not ChangeKind.EQUIVALENT

    def test_invalid_budget(self):
        old = Protego.parse("User-agent: *\nDisallow: /\n")
        new = Protego.parse("")
        with pytest.raises(ValueError, match="budget"):
            old.compare(new, "foobot", budget=0)

    def test_unknown_result_keeps_verifiable_partial_witnesses(self):
        old = Protego.parse("User-agent: *\nAllow: /\n")
        new = Protego.parse("User-agent: *\nDisallow: /\n")
        result = old.compare(new, "foobot", budget=1)
        assert result.kind is ChangeKind.UNKNOWN
        assert result.reason and "untested" in result.reason
        assert result.newly_blocked
        _assert_verified(result, old, new, "foobot")

    def test_robots_txt_is_never_reported_as_a_witness(self):
        old = Protego.parse("User-agent: *\nAllow: /\n")
        new = Protego.parse("User-agent: *\nDisallow: /\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.STRICTER
        assert all("robots.txt" not in url for url in result.newly_blocked)
        _assert_verified(result, old, new, "foobot")

    def test_leading_asterisk_patterns_contribute_candidates(self):
        old = Protego.parse("User-agent: *\nDisallow: /a.pdf\n")
        new = Protego.parse("User-agent: *\nDisallow: *.pdf\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.STRICTER
        assert "http://robotstxt-witness.invalid/x.pdf" in result.newly_blocked
        _assert_verified(result, old, new, "foobot")

    def test_result_is_a_namedtuple_with_public_symbols(self):
        old = Protego.parse("")
        new = Protego.parse("")
        result = old.compare(new, "foobot")
        assert isinstance(result, ComparisonResult)
        assert {kind.value for kind in ChangeKind} == {
            "equivalent",
            "stricter",
            "looser",
            "mixed",
            "unknown",
        }

    def test_wildcard_fillings_cover_empty_and_nested_gaps(self):
        old = Protego.parse("User-agent: *\nDisallow: /a/*/c\n")
        new = Protego.parse("User-agent: *\nDisallow: /a/x/c\n")
        result = old.compare(new, "foobot")
        assert result.kind is ChangeKind.LOOSER
        # The empty-gap path "/a//c" and a nested-gap path are both witnessed.
        assert "http://robotstxt-witness.invalid/a//c" in result.newly_allowed
        assert "http://robotstxt-witness.invalid/a/a/b/c" in result.newly_allowed
        _assert_verified(result, old, new, "foobot")


def test_random_policies_agree_with_exhaustive_enumeration():
    """For any pair of short rule tables, the reported witnesses must be
    genuine differences and the label must match an exhaustive evaluation of
    the same candidate space.
    """
    atoms = [
        "/", "/a", "/a/", "/b", "/app/", "*.php", "/a/*/c", "/tmp$",
        "/café/", "/x", "/*.inc", "/public/x", "/*/end$",
    ]

    def random_policy() -> Protego:
        lines = []
        for _ in range(random.randint(0, 6)):
            if not lines or random.random() < 0.1:
                lines.append("User-agent: *")
            field = random.choice(["Disallow", "Allow"])
            lines.append(f"{field}: {random.choice(atoms)}")
        return Protego.parse("\n".join(lines))

    rng = random.Random(42)
    for _ in range(500):
        old = random_policy()
        new = random_policy()
        ua = rng.choice(["foobot", "otherbot"])
        result = old.compare(new, ua)

        _assert_verified(result, old, new, ua)

        blocked = []
        allowed = []
        for path in _candidate_paths((old, new), ua):
            url = _to_url(path)
            old_allows = old.can_fetch(url, ua)
            new_allows = new.can_fetch(url, ua)
            if old_allows != new_allows:
                (allowed if new_allows else blocked).append(url)

        if result.kind is ChangeKind.UNKNOWN:
            continue
        if blocked and allowed:
            expected = ChangeKind.MIXED
        elif blocked:
            expected = ChangeKind.STRICTER
        elif allowed:
            expected = ChangeKind.LOOSER
        else:
            expected = ChangeKind.EQUIVALENT
        assert result.kind is expected
        if blocked or allowed:
            assert result.newly_blocked or result.newly_allowed
