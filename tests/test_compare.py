import pytest

from protego import (
    ComparisonBudget,
    PolicyComparison,
    Protego,
    Relation,
    Witness,
    compare_policies,
    compare_robotstxt,
)


def _recheck(result: PolicyComparison, old: Protego, new: Protego) -> None:
    """Every witness must match the real can_fetch decision on both sides."""
    for witness in result.witnesses:
        assert old.can_fetch(witness.url, result.user_agent) is witness.old_allowed
        assert new.can_fetch(witness.url, result.user_agent) is witness.new_allowed
        # The two sides disagree, otherwise the witness proves nothing.
        assert witness.old_allowed != witness.new_allowed


class TestRelation:
    def test_equivalent_identical_text(self):
        text = "User-agent: *\nDisallow: /a\nAllow: /a/b\n"
        result = compare_robotstxt(text, text, "*")
        assert result.relation is Relation.EQUIVALENT
        assert result.witnesses == ()
        assert result.unknown_reason is None

    def test_equivalent_different_text_same_policy(self):
        # Rule order does not matter once priorities are applied.
        old = "User-agent: *\nDisallow: /\nAllow: /page\n"
        new = "User-agent: *\nAllow: /page\nDisallow: /\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.EQUIVALENT

    def test_stricter(self):
        old = "User-agent: *\nDisallow: /a\n"
        new = "User-agent: *\nDisallow: /a\nDisallow: /b\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        assert len(result.witnesses) == 1
        witness = result.witnesses[0]
        assert witness.old_allowed is True
        assert witness.new_allowed is False
        old, new_parser = Protego.parse(old), Protego.parse(new)
        _recheck(result, old, new_parser)

    def test_looser(self):
        old = "User-agent: *\nDisallow: /\n"
        new = "User-agent: *\nDisallow: /a\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.LOOSER
        witness = result.witnesses[0]
        assert witness.old_allowed is False
        assert witness.new_allowed is True
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_both_directions(self):
        old = "User-agent: *\nDisallow: /a\nAllow: /b\n"
        new = "User-agent: *\nAllow: /a\nDisallow: /b\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.BOTH
        assert len(result.witnesses) == 2
        directions = {(w.old_allowed, w.new_allowed) for w in result.witnesses}
        assert directions == {(True, False), (False, True)}
        _recheck(result, Protego.parse(old), Protego.parse(new))


class TestPrecedence:
    def test_shadowed_disallow_is_equivalent(self):
        # A higher-priority, longer allow masks the shorter disallow, so
        # adding the disallow changes nothing.
        old = "User-agent: *\nAllow: /a\n"
        new = "User-agent: *\nAllow: /a\nDisallow: /a\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.EQUIVALENT

    def test_tie_allow_wins_equivalent(self):
        # Equal-length allow and disallow: allow always wins, so an extra
        # disallow on the same prefix has no effect.
        old = "User-agent: *\nAllow: /x\n"
        new = "User-agent: *\nAllow: /x\nDisallow: /x\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.EQUIVALENT

    def test_shorter_allow_does_not_mask_longer_disallow(self):
        old = "User-agent: *\nAllow: /x/\n"
        new = "User-agent: *\nDisallow: /x/page.html\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        assert result.witnesses[0].url.endswith("/x/page.html")
        _recheck(result, Protego.parse(old), Protego.parse(new))


class TestWildcardsAndAnchors:
    def test_anchor_tightens_wildcard(self):
        # "/*.php" blocks every path containing ".php"; the anchored version
        # only blocks paths ending in ".php", so the change is looser.
        old = "User-agent: *\nDisallow: /*.php\n"
        new = "User-agent: *\nDisallow: /*.php$\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.LOOSER
        witness = result.witnesses[0]
        assert witness.url.endswith(".php/") or ".php" in witness.url
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_same_prefix_wildcard_crossing_is_both(self):
        old = "User-agent: *\nDisallow: /a/*/x\n"
        new = "User-agent: *\nAllow: /a/b/x/y\n"
        result = compare_robotstxt(old, new, "*")
        # The allow opens a formerly blocked continuation while the wildcard
        # disallow keeps blocking every other matching path.
        assert result.relation is Relation.LOOSER
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_wildcard_crossing_both_directions(self):
        # Two overlapping wildcard prefixes reshuffle the blocked set in both
        # directions, so neither policy contains the other.
        old = "User-agent: *\nDisallow: /a/*/x\nAllow: /a/b/y\n"
        new = "User-agent: *\nAllow: /a/b/x\nDisallow: /a/*/y\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.BOTH
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_exact_anchor_vs_prefix(self):
        old = "User-agent: *\nDisallow: /x$\n"
        new = "User-agent: *\nDisallow: /x\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        witness = result.witnesses[0]
        assert witness.old_allowed is True
        assert witness.new_allowed is False
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_multiple_wildcards_backtracking(self):
        # Greedy wildcard matching with backtracking must be modeled exactly.
        old = "User-agent: *\nDisallow: /*-?*\n"
        new = "User-agent: *\nDisallow: /\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        _recheck(result, Protego.parse(old), Protego.parse(new))


class TestEscaping:
    def test_unicode_path_witness(self):
        # The library percent-escapes non-ASCII characters in both rules and
        # URLs, so a blocked ASCII prefix and an opened Unicode path produce a
        # real, encodable witness.
        old = "User-agent: *\nDisallow: /\n"
        new = "User-agent: *\nAllow: /\n"
        result = compare_robotstxt(old, new, "*")
        # A Unicode URL is normalized to percent-encoding before matching.
        unicode_url = "https://host.invalid/caf\u00e9/drink"
        old_parser, new_parser = Protego.parse(old), Protego.parse(new)
        assert old_parser.can_fetch(unicode_url, "*") is False
        assert new_parser.can_fetch(unicode_url, "*") is True

    def test_unicode_rule_normalized_like_url(self):
        # A non-ASCII rule and its percent-escaped spelling are the same
        # policy, so the comparison reports equivalence rather than a change.
        raw = "User-agent: *\nDisallow: /caf\u00e9/\n"
        escaped = "User-agent: *\nDisallow: /caf%C3%A9/\n"
        result = compare_robotstxt(raw, escaped, "*")
        assert result.relation is Relation.EQUIVALENT

    def test_percent_escaped_literal(self):
        old = "User-agent: *\nDisallow: /a%3Db\n"
        new = "User-agent: *\nAllow: /\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.LOOSER
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_dollar_literal_vs_anchor(self):
        # An escaped dollar is a literal character, not an anchor.
        old = "User-agent: *\nDisallow: /price$ \n"
        new = "User-agent: *\nDisallow: /price%24d\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation in {
            Relation.STRICTER,
            Relation.LOOSER,
            Relation.BOTH,
        }
        _recheck(result, Protego.parse(old), Protego.parse(new))


class TestAgentSelection:
    def test_specific_group_preferred_over_wildcard(self):
        old = (
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nAllow: /\n"
        )
        new = (
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nDisallow: /secret\n"
        )
        result = compare_robotstxt(old, new, "Mozilla/5.0 (compatible; FooBot/1.0)")
        assert result.old_group == "foobot"
        assert result.new_group == "foobot"
        assert result.relation is Relation.STRICTER
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_wildcard_group_used_for_other_agent(self):
        old = (
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nAllow: /\n"
        )
        new = (
            "User-agent: *\nDisallow: /\n"
            "User-agent: foobot\nDisallow: /secret\n"
        )
        result = compare_robotstxt(old, new, "barbot")
        assert result.old_group == "*"
        assert result.relation is Relation.EQUIVALENT

    def test_no_matching_group_is_fully_allowed(self):
        old = "User-agent: x\nDisallow: /\n"
        new = "User-agent: y\nDisallow: /secret\n"
        result = compare_robotstxt(old, new, "z")
        assert result.old_group is None
        assert result.new_group is None
        assert result.relation is Relation.EQUIVALENT


class TestRobotsTxt:
    def test_robots_txt_never_a_witness(self):
        old = "User-agent: *\nDisallow: /robots.txt\n"
        new = "User-agent: *\nAllow: /\n"
        result = compare_robotstxt(old, new, "*")
        # can_fetch always allows /robots.txt, so the policies are
        # equivalent on the fetchable path space.
        assert result.relation is Relation.EQUIVALENT
        assert all("/robots.txt" not in w.url for w in result.witnesses)


class TestNormalizedUniverse:
    def test_universe_matches_quote_fixed_point(self):
        import itertools

        from protego._compare import _build_alphabet, _universe_dfa
        from protego._utils import _quote_path

        representatives = _build_alphabet([], [])
        universe = _universe_dfa(representatives)
        index = {char: i for i, char in enumerate(representatives)}
        characters = [
            char
            for char in "/?#:@%ab0123456789ABCDEF.-"
            if char in index
        ]

        def accepts(path: str) -> bool:
            state = 0
            for char in path:
                state = universe.transitions[state][index[char]]
            return state in universe.accepting

        paths = [""]
        for _ in range(4):
            paths = list(paths) + [
                path + char for path in list(paths) for char in characters
            ]
        for path in paths:
            if not path:
                continue
            stable = _quote_path("https://host.invalid" + path) == path
            expected = stable and path != "/robots.txt"
            assert accepts(path) is expected, path

    def test_leading_double_slash_path_is_comparable(self):
        # A leading "//" is a path (not an authority) once the string arrives
        # as the path of a full URL, so a rule targeting it must be compared.
        old = "User-agent: *\nAllow: /\n"
        new = "User-agent: *\nDisallow: //*%00\nAllow: /\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        witness = result.witnesses[0]
        assert witness.url.split(".invalid")[1].startswith("//")
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_truncated_percent_escape_is_stable_path(self):
        # Truncated escapes such as "/%a" survive quoting inside a full URL.
        old = "User-agent: *\nAllow: /\n"
        new = "User-agent: *\nDisallow: /%a\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.STRICTER
        _recheck(result, Protego.parse(old), Protego.parse(new))

    def test_invalid_percent_byte_is_excluded(self):
        # "%aa" names a byte quoting rewrites into the replacement character,
        # so it is not a normalized-space witness; valid "%20" still is.
        old = "User-agent: *\nDisallow: /\n"
        new = "User-agent: *\nDisallow: /x%20y\n"
        result = compare_robotstxt(old, new, "*")
        assert result.relation is Relation.LOOSER
        assert all("%aa" not in w.url for w in result.witnesses)


class TestUnknown:
    def test_budget_exhaustion_returns_unknown_with_reason(self):
        old = "User-agent: *\nDisallow: /*a*b*c*d*e*f*g*h*i*j*k*l\n"
        new = "User-agent: *\nDisallow: /*a*b*c*d*e*f*g*h*i*j*k*l*m\n"
        result = compare_robotstxt(
            old, new, "*", budget=ComparisonBudget(max_rule_states=20)
        )
        assert result.relation is Relation.UNKNOWN
        assert result.unknown_reason is not None
        assert "budget" in result.unknown_reason

    def test_product_state_budget_returns_unknown(self):
        old = "User-agent: *\nDisallow: /\n"
        new = "User-agent: *\nAllow: /\n"
        result = compare_robotstxt(
            old, new, "*", budget=ComparisonBudget(max_product_states=3)
        )
        assert result.relation is Relation.UNKNOWN
        assert result.unknown_reason is not None


class TestAutomatonFidelity:
    @pytest.mark.parametrize("seed", range(30))
    def test_automaton_matches_can_fetch_on_enumerated_paths(self, seed):
        import random

        from protego._compare import (
            _build_alphabet,
            _build_rule_dfas,
            _decide,
            _flat_rules,
            _matched_rule_set,
        )

        rng = random.Random(seed)
        tokens = ["/", "a", "b", "*", "$", "?", "-", ".", "%20"]

        def random_rule() -> str:
            pattern = "/" + "".join(
                rng.choice(tokens) for _ in range(rng.randint(0, 3))
            )
            return pattern + "$" if rng.random() < 0.3 else pattern

        lines = ["User-agent: *"]
        for _ in range(rng.randint(1, 4)):
            directive = rng.choice(["Allow", "Disallow"])
            lines.append(f"{directive}: {random_rule()}")
        parser = Protego.parse("\n".join(lines) + "\n")

        rule_set, _ = _matched_rule_set(parser, "bot")
        rules = _flat_rules(rule_set) if rule_set is not None else []
        # The production alphabet gives every rule literal its own class.
        representatives = _build_alphabet([], rules)
        dfas = _build_rule_dfas(rules, representatives, ComparisonBudget())
        literals = set(representatives)
        rest_index = len(representatives) - 1

        def automaton_decision(path: str) -> bool:
            states = tuple(0 for _ in dfas)
            for char in path:
                index = (
                    representatives.index(char)
                    if char in literals
                    else rest_index
                )
                states = tuple(
                    dfa.transitions[state][index]
                    for (dfa, _), state in zip(dfas, states, strict=True)
                )
            return _decide(dfas, states)

        # A bare "?" is normalized into "%3F" inside rule patterns, so it is
        # not a model-space literal here; enumerate only modeled characters.
        alphabet = "/ab-."
        paths = ["/"]
        for _ in range(5):
            paths = list(paths) + [
                path + char
                for path in list(paths)
                for char in alphabet
                if not (char == "/" and path.endswith("/"))
            ]
        for path in set(paths):
            url = "https://host.invalid" + path
            assert automaton_decision(path) == parser.can_fetch(url, "bot")

    def test_result_types(self):
        result = compare_robotstxt(
            "User-agent: *\nDisallow: /a\n",
            "User-agent: *\nDisallow: /b\n",
            "*",
        )
        assert isinstance(result, PolicyComparison)
        assert all(isinstance(w, Witness) for w in result.witnesses)
