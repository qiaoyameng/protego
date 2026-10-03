import random

import pytest

from protego import PolicyDiff, Protego
from protego._compare import (
    _CompiledPolicy,
    _CompiledRule,
    _Stepper,
    _fetch_input,
    _initial_state,
    _verdict,
    enumerate_first_difference,
)
from protego._urlpattern import _URLPattern


def _compile_single(pattern: str) -> _CompiledPolicy:
    """Compile one already-normalized pattern the way _compile_policy does."""
    p = _URLPattern(pattern)
    if p._contains_asterisk:
        rule = _CompiledRule(
            "disallow",
            p.priority,
            "wildcard",
            "",
            tuple(p._wildcard_parts),
            p._wildcard_ends_with_dollar,
        )
    elif p._contains_dollar:
        rule = _CompiledRule("disallow", p.priority, "exact", p._pattern[:-1], (), False)
    else:
        rule = _CompiledRule("disallow", p.priority, "prefix", p._pattern, (), False)
    return _CompiledPolicy((rule,))


def _matches(pattern: str, path: str) -> bool:
    """Feed *path* to the compiled matcher of *pattern*, char by char."""
    policy = _compile_single(pattern)
    stepper = _Stepper(policy)
    state = _initial_state(policy)
    for char in path:
        state = stepper.step(state, char)
    return not _verdict(policy, state)  # the single rule is a disallow


class TestCompiledMatcher:
    """The per-rule matchers of the comparison engine must agree with
    _URLPattern.match, which can_fetch() uses."""

    @pytest.mark.parametrize("seed", range(30))
    def test_against_url_pattern(self, seed):
        rng = random.Random(seed)
        for _ in range(40):
            pattern = "/" + "".join(rng.choice("a/*") for _ in range(rng.randint(0, 5)))
            if rng.random() < 0.4:
                pattern += "$"
            path = "/" + "".join(rng.choice("a/b") for _ in range(rng.randint(0, 6)))
            assert _matches(pattern, path) == _URLPattern(pattern).match(path), (
                pattern,
                path,
            )

    def test_known_tricky_cases(self):
        # (pattern, path, expected)
        cases = [
            ("/a*$", "/ab", True),  # an empty last part matches anything
            ("a*b$", "aab", True),  # the last part may start late
            ("a*aa$", "aaaa", True),  # overlapping occurrences of the last part
            ("a*aa$", "aaxaa", True),
            ("a*aa$", "aaxa", False),
            ("*", "/anything", True),
            ("*$", "/anything", True),
            ("/*", "/", True),
            ("/$", "/", True),
            ("/$", "/x", False),
            ("/a*b*c", "/aXXbYYc", True),
            ("/a*b*c", "/aXXbYYcZ", True),
            ("/a*b*c$", "/aXXbYYcZ", False),
            ("/a*b*c$", "/acb", False),  # parts must appear in order
            ("/foo", "/foobar", True),
            ("/foo", "/fo", False),
            ("/foo$", "/foo", True),
            ("/foo$", "/foobar", False),
        ]
        for pattern, path, expected in cases:
            assert _matches(pattern, path) == expected, (pattern, path)


class TestComparePolicy:
    def test_newly_disallowed_path(self):
        old = Protego.parse("User-agent: *\n")
        new = Protego.parse("User-agent: *\nDisallow: /private\n")
        diff = old.compare_policy(new, "mybot")
        assert diff == PolicyDiff("different", "/private", True, False, diff.states_explored)
        assert not new.can_fetch(diff.path, "mybot")
        assert old.can_fetch(diff.path, "mybot")

    def test_newly_allowed_path(self):
        old = Protego.parse("User-agent: *\nDisallow: /private\n")
        new = Protego.parse("User-agent: *\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/private"
        assert diff.old_allowed is False
        assert diff.new_allowed is True

    def test_identical_policies_are_equivalent(self):
        content = "User-agent: *\nDisallow: /a\nAllow: /ab\nDisallow: /c*$"
        rp1 = Protego.parse(content)
        rp2 = Protego.parse(content)
        assert rp1.compare_policy(rp2, "mybot").status == "equivalent"

    def test_rule_order_and_duplicates_do_not_matter(self):
        old = Protego.parse("User-agent: *\nDisallow: /a\nAllow: /ab\nDisallow: /c")
        new = Protego.parse(
            "User-agent: *\nDisallow: /c\nDisallow: /a\nDisallow: /a\nAllow: /ab"
        )
        assert old.compare_policy(new, "mybot").status == "equivalent"

    def test_allow_wins_ties(self):
        # A new Allow line flips the verdict even though the Disallow
        # line was already there: diffing Disallow lines alone would
        # miss this.
        old = Protego.parse("User-agent: *\nDisallow: /x\n")
        new = Protego.parse("User-agent: *\nDisallow: /x\nAllow: /x\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/x"
        assert (diff.old_allowed, diff.new_allowed) == (False, True)

    def test_length_based_precedence(self):
        # The longer Allow rule takes precedence over the shorter
        # Disallow rule; removing it changes only longer paths.
        old = Protego.parse("User-agent: *\nDisallow: /a\nAllow: /ab\n")
        new = Protego.parse("User-agent: *\nDisallow: /a\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/ab"
        assert (diff.old_allowed, diff.new_allowed) == (True, False)
        # "/a" itself is disallowed by both.
        assert not old.can_fetch("/a", "mybot")
        assert not new.can_fetch("/a", "mybot")

    def test_trailing_dollar(self):
        old = Protego.parse("User-agent: *\nDisallow: /tmp\n")
        new = Protego.parse("User-agent: *\nDisallow: /tmp$\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/tmp/"
        assert (diff.old_allowed, diff.new_allowed) == (False, True)

    def test_wildcard(self):
        old = Protego.parse("User-agent: *\nDisallow: /*.pdf\n")
        new = Protego.parse("User-agent: *\nDisallow: /*.pdf$\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/.pdf/"
        assert (diff.old_allowed, diff.new_allowed) == (False, True)

    def test_sample_url_lists_miss_this_difference(self):
        # The difference hides one character past the rule literals, so
        # a sample list built from the rules themselves never sees it.
        old = Protego.parse("User-agent: *\nDisallow: /api/\nAllow: /api/public\n")
        new = Protego.parse("User-agent: *\nDisallow: /api/\nAllow: /api/public$\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/api/public/"
        assert (diff.old_allowed, diff.new_allowed) == (True, False)
        # Every URL a sample list derived from the rule literals would
        # try gets the same verdict from both versions.
        for sample in ("/api/", "/api/public"):
            assert old.can_fetch(sample, "mybot") == new.can_fetch(sample, "mybot")

    def test_counterexample_is_shortest(self):
        old = Protego.parse("User-agent: *\nDisallow: /a/b/c/d\n")
        new = Protego.parse("User-agent: *\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.path == "/a/b/c/d"

    def test_percent_encoding_spellings_are_equivalent(self):
        old = Protego.parse("User-agent: *\nDisallow: /café\nDisallow: /a b\n")
        new = Protego.parse("User-agent: *\nDisallow: /caf%C3%A9\nDisallow: /a%20b\n")
        assert old.compare_policy(new, "mybot").status == "equivalent"

    def test_encoded_slash_is_not_a_literal_slash(self):
        old = Protego.parse("User-agent: *\nDisallow: /a%2Fb\n")
        new = Protego.parse("User-agent: *\nDisallow: /a/b\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/a/b"
        assert (diff.old_allowed, diff.new_allowed) == (True, False)

    def test_robots_txt_is_always_allowed(self):
        old = Protego.parse("User-agent: *\nDisallow: /robots.txt\n")
        new = Protego.parse("User-agent: *\n")
        assert old.compare_policy(new, "mybot").status == "equivalent"

    def test_user_agent_selection(self):
        old = Protego.parse("User-agent: foo\nDisallow: /x\n")
        new = Protego.parse("User-agent: *\n")
        # "foo" gets rules in the old file but not in the new one.
        diff = old.compare_policy(new, "foo")
        assert diff.status == "different"
        assert diff.path == "/x"
        # "bar" matches no group with rules in either file.
        assert old.compare_policy(new, "bar").status == "equivalent"

    def test_more_specific_group_in_new_version(self):
        old = Protego.parse("User-agent: *\nDisallow: /a\n")
        new = Protego.parse(
            "User-agent: *\nDisallow: /a\nUser-agent: foo\nDisallow: /b\n"
        )
        assert old.compare_policy(new, "bar").status == "equivalent"
        diff = old.compare_policy(new, "foo")
        assert diff.status == "different"
        # "foo" now gets its own group, so the "*" group no longer
        # applies to it: "/a" becomes allowed, "/b" becomes disallowed.
        assert diff.path == "/a"
        assert (diff.old_allowed, diff.new_allowed) == (False, True)

    def test_budget_exhaustion_is_unproven_not_equivalent(self):
        content = "User-agent: *\nDisallow: /a\n"
        old = Protego.parse(content)
        # Textually different but equivalent, so the search, not the
        # identical-policy shortcut, decides.
        new = Protego.parse("User-agent: *\nDisallow: /a\nDisallow: /a\n")
        diff = old.compare_policy(new, "mybot", max_states=1)
        assert diff.status == "unproven"
        assert diff.path is None
        assert diff.states_explored == 1
        # The same pair is proved equivalent with enough budget.
        assert old.compare_policy(new, "mybot", max_states=3).status == "equivalent"
        # A tiny budget must not hide a real difference either: it is
        # reported only while states remain.
        other = Protego.parse("User-agent: *\nDisallow: /a/b\n")
        diff = old.compare_policy(other, "mybot", max_states=1)
        assert diff.status == "unproven"
        diff = old.compare_policy(other, "mybot")
        assert diff.status == "different"
        assert diff.path == "/a"

    def test_invalid_max_states(self):
        rp = Protego.parse("User-agent: *\n")
        with pytest.raises(ValueError, match="max_states"):
            rp.compare_policy(rp, "mybot", max_states=0)

    def test_difference_at_the_root(self):
        old = Protego.parse("User-agent: *\nDisallow: /\n")
        new = Protego.parse("User-agent: *\n")
        diff = old.compare_policy(new, "mybot")
        assert diff.status == "different"
        assert diff.path == "/"
        assert (diff.old_allowed, diff.new_allowed) == (False, True)


def _random_robotstxt(rng):
    lines = ["User-agent: *"]
    for _ in range(rng.randint(1, 4)):
        field = rng.choice(["Allow", "Disallow"])
        pattern = "/" + "".join(rng.choice("a/") for _ in range(rng.randint(0, 3)))
        if rng.random() < 0.4:
            pos = rng.randint(0, len(pattern))
            pattern = pattern[:pos] + "*" + pattern[pos:]
        if rng.random() < 0.3:
            pattern += "$"
        lines.append(f"{field}: {pattern}")
    return "\n".join(lines)


class TestCrossValidation:
    """Cross-validate the engine against an independent brute-force
    enumeration of can_fetch() over a small alphabet."""

    @pytest.mark.parametrize("seed", range(100))
    def test_against_enumeration(self, seed):
        rng = random.Random(seed)
        old = Protego.parse(_random_robotstxt(rng))
        new = Protego.parse(_random_robotstxt(rng))
        diff = old.compare_policy(new, "mybot")
        assert diff.status != "unproven"
        found = enumerate_first_difference(
            old, new, "mybot", alphabet="/ab", max_length=7
        )
        if diff.status == "equivalent":
            assert found is None
            return
        assert diff.status == "different"
        assert found is not None
        # Both searches report a shortest counterexample over the same
        # effective alphabet, hence of the same length and with the
        # same verdicts.
        assert len(found[0]) == len(diff.path)
        assert (found[1], found[2]) == (diff.old_allowed, diff.new_allowed)
        # And the reported path really is a counterexample.
        assert old.can_fetch(_fetch_input(diff.path), "mybot") == diff.old_allowed
        assert new.can_fetch(_fetch_input(diff.path), "mybot") == diff.new_allowed

    def test_enumerate_first_difference(self):
        old = Protego.parse("User-agent: *\n")
        new = Protego.parse("User-agent: *\nDisallow: /ba\n")
        assert enumerate_first_difference(
            old, new, "mybot", alphabet="/ab", max_length=4
        ) == ("/ba", True, False)
        assert (
            enumerate_first_difference(old, new, "mybot", alphabet="/a", max_length=4)
            is None
        )
