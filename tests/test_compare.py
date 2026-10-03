import random

import pytest

from protego import Protego, compare_policies
from protego._compare import (
    DIFFERENT,
    EQUIVALENT,
    UNDETERMINED,
    brute_force_difference,
)


def parse(content):
    return Protego.parse(f"User-agent: *\n{content}")


class TestComparePolicies:
    def test_identical_versions_are_equivalent(self):
        old = parse("Disallow: /private\nAllow: /private/public$\nDisallow: /*.gif$")
        new = parse("Disallow: /private\nAllow: /private/public$\nDisallow: /*.gif$")
        result = compare_policies(old, new, "mybot")
        assert result.status == EQUIVALENT
        assert result.path is None

    def test_empty_versions_are_equivalent(self):
        result = compare_policies(Protego.parse(""), Protego.parse(""), "mybot")
        assert result.status == EQUIVALENT

    def test_added_disallow_is_reported(self):
        old = parse("Disallow: /tmp")
        new = parse("Disallow: /tmp\nDisallow: /private")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/private"
        assert result.old_verdict is True
        assert result.new_verdict is False

    def test_removed_allow_is_reported(self):
        # No Disallow line changed, yet the policy changed: the removed
        # Allow used to outrank the Disallow by length.
        old = parse("Disallow: /x\nAllow: /x/y/z")
        new = parse("Disallow: /x")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/x/y/z"
        assert result.old_verdict is True
        assert result.new_verdict is False

    def test_added_disallow_can_be_a_no_op(self):
        # The added Disallow line changes nothing: /a already covers every
        # path /ab covers, and the Allow outranks both. A line-based diff
        # would flag this as a policy change; it is not one.
        old = parse("Disallow: /a\nAllow: /abc")
        new = parse("Disallow: /a\nDisallow: /ab\nAllow: /abc")
        result = compare_policies(old, new, "mybot")
        assert result.status == EQUIVALENT

    def test_allow_wins_on_equal_length(self):
        old = parse("Disallow: /x\nAllow: /x")
        new = parse("Disallow: /x")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/x"
        assert result.old_verdict is True
        assert result.new_verdict is False

    def test_dollar_anchor_difference(self):
        old = parse("Disallow: /a$")
        new = parse("Disallow: /a")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path.startswith("/a")
        assert len(result.path) == 3
        assert result.old_verdict is True
        assert result.new_verdict is False

    def test_wildcard_matches_empty_and_slashes(self):
        # "*" matches any sequence, including an empty one, so the old
        # "/*/" pattern does not cover /cdn/public/ while the new plain
        # prefix does.
        old = parse("Disallow: /cdn/\nAllow: /cdn/*/public/")
        new = parse("Disallow: /cdn/\nAllow: /cdn/public/")
        assert old.can_fetch("/cdn/x/public/logo.png", "mybot")
        assert not new.can_fetch("/cdn/x/public/logo.png", "mybot")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/cdn/public/"
        assert result.old_verdict is False
        assert result.new_verdict is True

    def test_shortest_counterexample_is_returned(self):
        old = parse("")
        new = parse("Disallow: /aaaa\nDisallow: /b")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/b"

    def test_percent_encoding_is_normalized(self):
        old = parse("")
        new = parse("Disallow: /a b")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/a%20b"
        assert result.old_verdict is True
        assert result.new_verdict is False
        # The reported path is the normalized form of both spellings.
        assert new.can_fetch("/a b", "mybot") is False
        assert new.can_fetch("/a%20b", "mybot") is False

    def test_robots_txt_itself_is_always_allowed(self):
        # Textually different, but the only path the "$" rule adds over
        # the "%24" rule is /robots.txt itself, which is always allowed.
        old = parse("Disallow: /robots.txt$")
        new = parse("Disallow: /robots.txt%24")
        result = compare_policies(old, new, "mybot")
        assert result.status == EQUIVALENT

    def test_robots_txt_prefix_rule_still_differs_elsewhere(self):
        # The carve-out only covers /robots.txt itself (and its query
        # form); a prefix rule still changes the verdict of other paths.
        old = parse("Disallow: /robots.txt")
        new = parse("")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path.startswith("/robots.txt")
        assert result.path != "/robots.txt"
        assert result.old_verdict is False
        assert result.new_verdict is True

    def test_index_html_expansion_is_honored(self):
        old = parse("Disallow: /\nAllow: /index.html")
        new = parse("Disallow: /")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/"
        assert result.old_verdict is True
        assert result.new_verdict is False

    def test_user_agent_group_selection(self):
        old = Protego.parse(
            "User-agent: googlebot\nDisallow: /g\n\nUser-agent: *\nDisallow: /a\n"
        )
        new = Protego.parse(
            "User-agent: googlebot\nDisallow: /g\n\n"
            "User-agent: *\nDisallow: /a\nDisallow: /b\n"
        )
        assert compare_policies(old, new, "googlebot").status == EQUIVALENT
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert result.path == "/b"

    def test_budget_exhaustion_is_undetermined_not_equivalent(self):
        old = parse("Disallow: /a*b*c*d*e*f*g*h")
        new = parse("Disallow: /a*b*c*d*e*f*g*i")
        result = compare_policies(old, new, "mybot", max_states=3)
        assert result.status == UNDETERMINED
        assert result.path is None
        assert result.reason is not None

    def test_invalid_budget_is_rejected(self):
        with pytest.raises(ValueError):
            compare_policies(parse(""), parse(""), "mybot", max_states=0)

    def test_reported_verdicts_match_public_api(self):
        old = parse("Disallow: /x*\nAllow: /xyz$")
        new = parse("Disallow: /x*")
        result = compare_policies(old, new, "mybot")
        assert result.status == DIFFERENT
        assert old.can_fetch(result.path, "mybot") == result.old_verdict
        assert new.can_fetch(result.path, "mybot") == result.new_verdict


class TestBruteForceCrossCheck:
    """Cross-validate the comparator against independent enumeration."""

    CASES = [
        ("Disallow: /a\nAllow: /ab", "Disallow: /a"),
        ("Disallow: /a$", "Disallow: /a"),
        ("Disallow: /*/b", "Disallow: /a/b\nAllow: /a/b$"),
        ("Allow: /a*b\nDisallow: /", "Disallow: /\nAllow: /a*b$"),
        ("Disallow: /a*b*c", "Disallow: /a*b\nAllow: /a*b*c"),
        ("Disallow: /%41", "Disallow: /A"),
        ("Disallow: /a\nDisallow: /b$", "Disallow: /b$\nAllow: /a"),
        ("Allow: /$\nDisallow: /", "Disallow: /"),
    ]

    @pytest.mark.parametrize(("old_rules", "new_rules"), CASES)
    def test_matches_brute_force(self, old_rules, new_rules):
        old = parse(old_rules)
        new = parse(new_rules)
        result = compare_policies(old, new, "mybot")
        brute = brute_force_difference(old, new, "mybot", max_length=6)
        if result.status == DIFFERENT:
            assert brute is not None
            brute_path, brute_old, brute_new = brute
            # The comparator must find a shortest counterexample.
            assert len(result.path) == len(brute_path)
            assert (result.old_verdict, result.new_verdict) == (brute_old, brute_new)
        else:
            assert result.status == EQUIVALENT
            assert brute is None

    def test_random_small_rule_sets(self):
        rng = random.Random(20261003)
        atoms = ["/a", "/b", "/ab", "/ba", "/", "/*", "/a*", "*/b", "/a$b"]
        for _ in range(300):
            def random_rules():
                lines = []
                for _ in range(rng.randint(0, 4)):
                    field = rng.choice(["Allow", "Disallow"])
                    pattern = rng.choice(atoms)
                    if rng.random() < 0.3:
                        pattern += "$"
                    lines.append(f"{field}: {pattern}")
                return "\n".join(lines)

            old = parse(random_rules())
            new = parse(random_rules())
            result = compare_policies(old, new, "mybot")
            assert result.status in (DIFFERENT, EQUIVALENT)
            brute = brute_force_difference(old, new, "mybot", max_length=5)
            if result.status == DIFFERENT:
                assert brute is not None
                assert len(result.path) == len(brute[0])
                assert (result.old_verdict, result.new_verdict) == (brute[1], brute[2])
            else:
                assert brute is None
