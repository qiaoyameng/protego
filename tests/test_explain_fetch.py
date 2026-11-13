from protego import FetchExplanation, Protego, RuleMatch

CONTENT = (
    "User-agent: *\n"  # 1
    "Disallow: /private\n"  # 2
    "Disallow: /some path\n"  # 3
    "Allow: /private/public\n"  # 4
    "Disallow: /*.gif$\n"  # 5
    "Allow: /index.html\n"  # 6
    "User-agent: foo\n"  # 7
    "User-agent: foo\n"  # 8
    "Disallow: /foo\n"  # 9
    "Allow: /foo\n"  # 10
)

URLS = [
    ("https://example.com/private/x", "*"),
    ("https://example.com/private/public/a", "*"),
    ("https://example.com/some%20path/x", "*"),
    ("https://example.com/img/logo.gif", "*"),
    ("https://example.com/img/logo.gifx", "*"),
    ("https://example.com/", "*"),
    ("https://example.com/index.html", "*"),
    ("https://example.com/foo", "foo"),
    ("https://example.com/foo/bar", "FooBar/1.0"),
    ("https://example.com/unrelated", "foo"),
    ("https://example.com/private/x", "bar"),
    ("https://example.com/robots.txt", "foo"),
]


class TestExplainFetch:
    def test_same_conclusion_as_can_fetch(self):
        rp = Protego.parse(CONTENT)
        for url, user_agent in URLS:
            explanation = rp.explain_fetch(url, user_agent)
            assert isinstance(explanation, FetchExplanation)
            assert explanation.allowed == rp.can_fetch(url, user_agent)

    def test_disallow_winner_points_to_source(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/private/x", "*")
        assert not explanation.allowed
        winner = explanation.winning_rule
        assert isinstance(winner, RuleMatch)
        assert winner.field == "disallow"
        assert winner.pattern == "/private"
        assert winner.line == 2
        assert winner.raw == "Disallow: /private"
        assert winner.derived_from is None
        assert "line 2" in explanation.reason

    def test_longer_allow_wins(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch(
            "https://example.com/private/public/a", "*"
        )
        assert explanation.allowed
        assert explanation.winning_rule.field == "allow"
        assert explanation.winning_rule.line == 4
        # The shorter disallow prefix matches too, and is reported.
        assert [m.line for m in explanation.other_matches] == [2]
        assert not explanation.truncated

    def test_escaping_is_traceable(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/some%20path/x", "*")
        assert not explanation.allowed
        winner = explanation.winning_rule
        # The normalized pattern used for matching...
        assert winner.pattern == "/some%20path"
        # ...points back to the line as written.
        assert winner.line == 3
        assert winner.raw == "Disallow: /some path"

    def test_wildcard_and_anchor(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/img/logo.gif", "*")
        assert not explanation.allowed
        assert explanation.winning_rule.pattern == "/*.gif$"
        assert explanation.winning_rule.line == 5

        explanation = rp.explain_fetch("https://example.com/img/logo.gifx", "*")
        assert explanation.allowed
        assert explanation.winning_rule is None
        assert "allowed by default" in explanation.reason

    def test_index_html_derived_rule(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/", "*")
        assert explanation.allowed
        winner = explanation.winning_rule
        assert winner.field == "allow"
        assert winner.pattern == "/$"
        assert winner.line == 6
        assert winner.raw == "Allow: /index.html"
        assert winner.derived_from is not None
        assert "auto-derived" in explanation.reason

        explanation = rp.explain_fetch("https://example.com/index.html", "*")
        assert explanation.allowed
        assert explanation.winning_rule.pattern == "/index.html"
        assert explanation.winning_rule.derived_from is None

    def test_dollar_escape_derived_rule(self):
        rp = Protego.parse("User-agent: *\nDisallow: /a$b\n")
        explanation = rp.explain_fetch("/a%24b", "*")
        assert not explanation.allowed
        winner = explanation.winning_rule
        assert winner.pattern == "/a%24b"
        assert winner.line == 2
        assert winner.raw == "Disallow: /a$b"
        assert winner.derived_from is not None
        assert "$" in winner.derived_from

    def test_allow_wins_equal_priority_tie(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/foo", "foo")
        assert explanation.allowed
        assert explanation.winning_rule.field == "allow"
        assert explanation.winning_rule.line == 10
        assert [m.line for m in explanation.other_matches] == [9]
        assert "allow takes precedence" in explanation.reason

    def test_merged_user_agent_group(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/foo", "FooBar/1.0")
        assert explanation.matched_user_agent == "foo"
        assert [line for line, _ in explanation.user_agent_lines] == [7, 8]
        assert "merged" in explanation.reason

    def test_no_matching_rule_defaults_to_allow(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/unrelated", "foo")
        assert explanation.allowed
        assert explanation.winning_rule is None
        assert explanation.matched_user_agent == "foo"
        assert "allowed by default" in explanation.reason

    def test_no_matching_group_defaults_to_allow(self):
        rp = Protego.parse("User-agent: foo\nDisallow: /private\n")
        explanation = rp.explain_fetch("https://example.com/private/x", "bar")
        assert explanation.allowed
        assert explanation.matched_user_agent is None
        assert explanation.winning_rule is None
        assert "allowed by default" in explanation.reason

    def test_robots_txt_itself(self):
        rp = Protego.parse(CONTENT)
        explanation = rp.explain_fetch("https://example.com/robots.txt", "foo")
        assert explanation.allowed
        assert explanation.winning_rule is None
        assert "robots.txt" in explanation.reason

    def test_other_matches_truncation(self):
        content = "User-agent: *\nDisallow: /a\nDisallow: /ab\nDisallow: /abc\n"
        rp = Protego.parse(content)
        explanation = rp.explain_fetch("/abc", "*")
        assert not explanation.allowed
        assert explanation.winning_rule.line == 4
        assert len(explanation.other_matches) == 2
        assert not explanation.truncated

        explanation = rp.explain_fetch("/abc", "*", max_other_matches=1)
        assert not explanation.allowed
        assert len(explanation.other_matches) == 1
        assert explanation.truncated

        explanation = rp.explain_fetch("/abc", "*", max_other_matches=None)
        assert len(explanation.other_matches) == 2
        assert not explanation.truncated

    def test_explain_uses_built_index(self):
        # Matching through can_fetch() first builds the index; explaining
        # afterwards must still go through the same rules and conclusion.
        rp = Protego.parse(CONTENT)
        for url, user_agent in URLS:
            rp.can_fetch(url, user_agent)
        for url, user_agent in URLS:
            assert rp.explain_fetch(url, user_agent).allowed == rp.can_fetch(
                url, user_agent
            )
