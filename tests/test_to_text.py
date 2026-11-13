from protego import Protego


def assert_round_trip(content, agents, urls):
    parsed = Protego.parse(content)
    text = parsed.to_text()
    reparsed = Protego.parse(text)

    assert reparsed.to_text() == text
    assert list(reparsed.sitemaps) == list(parsed.sitemaps)
    assert reparsed.preferred_host == parsed.preferred_host
    for agent in agents:
        assert reparsed.crawl_delay(agent) == parsed.crawl_delay(agent)
        assert reparsed.request_rate(agent) == parsed.request_rate(agent)
        assert reparsed.visit_time(agent) == parsed.visit_time(agent)
        for url in urls:
            assert reparsed.can_fetch(url, agent) == parsed.can_fetch(url, agent)


def test_to_text_normalizes_directives_and_encoding():
    content = """
    # a comment that is not kept
    USER-AGENT: *
    DISSALLOW: /private
    ALLOW: /private/public
    Crawl-delay: 10
    Request Rate: 100/15m 1820-1940
    Visit Time: 0400 0845
    Sitemap: https://site.local/sitemap.xml
    Host: www.site.local
    """
    assert Protego.parse(content).to_text() == (
        "User-agent: *\n"
        "Disallow: /private\n"
        "Allow: /private/public\n"
        "Crawl-delay: 10.0\n"
        "Request-rate: 100/900s 1820-1940\n"
        "Visit-time: 0400-0845\n"
        "\n"
        "Sitemap: https://site.local/sitemap.xml\n"
        "Host: www.site.local\n"
    )

    content = "User-agent: *\nDisallow: /a b\nDisallow: /ツ\nDisallow: /x%2fy\n"
    assert Protego.parse(content).to_text() == (
        "User-agent: *\n"
        "Disallow: /a%20b\n"
        "Disallow: /%E3%83%84\n"
        "Disallow: /x%2Fy\n"
    )


def test_to_text_keeps_duplicates_and_drops_empty_and_invalid_directives():
    content = (
        "User-agent: Foo\n"
        "Disallow:\n"
        "Allow:\n"
        "Disallow: /a\n"
        "Disallow: /a\n"
        "Crawl-delay: not-a-number\n"
        "Crawl-delay: 5\n"
        "Crawl-delay: 7\n"
        "Request-rate: 0/0\n"
        "Visit-time: 9-17\n"
    )
    text = Protego.parse(content).to_text()
    assert text == (
        "User-agent: foo\n"
        "Disallow: /a\n"
        "Disallow: /a\n"
        "Crawl-delay: 5.0\n"
        "Crawl-delay: 7.0\n"
    )
    assert text.count("Disallow: /a") == 2
    assert "Allow:" not in text
    assert Protego.parse(text).crawl_delay("foo") == 7.0


def test_to_text_does_not_write_derived_index_rule():
    content = "User-agent: Foo\nAllow: /allowed/index.html\nDisallow: /\n"
    parsed = Protego.parse(content)
    text = parsed.to_text()

    assert text == (
        "User-agent: foo\n"
        "Allow: /allowed/index.html\n"
        "Disallow: /\n"
    )
    assert "/allowed/$" not in text
    assert_round_trip(
        content,
        ["Foo", "foo", "Other"],
        [
            "http://example.com/allowed/",
            "http://example.com/allowed/index.html",
            "http://example.com/allowed/$budget",
            "http://example.com/other",
        ],
    )


def test_to_text_round_trips_duplicate_agents_dollars_and_comments():
    content = """
    # Comments are dropped, but a literal dollar sign is still a rule value.
    USER-AGENT: FooBot
    Disallow: /cash$/x
    Allow: /price$
    Disallow: /blocked

    User-agent: BarBot
    Allow: /bar$
    Disallow: /

    User-agent: FooBot
    Allow: /cash$/x/y
    Disallow: /foo/index.html
    """
    parsed = Protego.parse(content)
    text = parsed.to_text()

    assert text.count("User-agent: foobot") == 2
    assert "Allow: /price$" in text
    assert "Disallow: /foo/index.html" in text
    assert_round_trip(
        content,
        ["FooBot", "foobot", "BarBot", "barbot", "Other"],
        [
            "http://example.com/cash$/x/abc",
            "http://example.com/cash%24/x/abc",
            "http://example.com/cash$/x/y",
            "http://example.com/price",
            "http://example.com/price/",
            "http://example.com/price$",
            "http://example.com/blocked",
            "http://example.com/bar",
            "http://example.com/bar/",
            "http://example.com/foo/index.html",
            "http://example.com/foo/",
            "http://example.com/other",
        ],
    )


def test_to_text_keeps_empty_group_separate_from_the_next_group():
    content = (
        "User-agent: Foo\n"
        "Disallow:\n"
        "User-agent: *\n"
        "Disallow: /x\n"
    )
    text = Protego.parse(content).to_text()

    assert text == (
        "User-agent: foo\n"
        "Disallow:\n"
        "\n"
        "User-agent: *\n"
        "Disallow: /x\n"
    )
    assert_round_trip(
        content,
        ["Foo", "foo", "Other"],
        ["http://example.com/x", "http://example.com/y"],
    )


def test_to_text_does_not_write_derived_user_agent_aliases():
    content = "User-agent: foo*bot\nDisallow: /x\n"
    text = Protego.parse(content).to_text()

    assert text == "User-agent: foo*bot\nDisallow: /x\n"
    assert "User-agent: foobot" not in text
    assert_round_trip(
        content,
        ["foo*bot", "foobot", "Other"],
        ["http://example.com/x", "http://example.com/y"],
    )


def test_to_text_round_trips_time_policies():
    content = """
    User-agent: One
    Crawl-delay: 1e3
    Request-rate: 100/15m 1820-1940
    Visit-time: 0400 0845
    User-agent: Two
    Crawl-delay: 5
    Crawl-delay: 7
    Request-rate: 1/10
    Visit-time: 0200-0630
    """
    parsed = Protego.parse(content)
    text = parsed.to_text()

    assert text == (
        "User-agent: one\n"
        "Crawl-delay: 1000.0\n"
        "Request-rate: 100/900s 1820-1940\n"
        "Visit-time: 0400-0845\n"
        "\n"
        "User-agent: two\n"
        "Crawl-delay: 5.0\n"
        "Crawl-delay: 7.0\n"
        "Request-rate: 1/10s\n"
        "Visit-time: 0200-0630\n"
    )
    assert_round_trip(
        content,
        ["One", "one", "Two", "two", "Other"],
        ["http://example.com/"],
    )


def test_to_text_keeps_site_wide_directives_in_source_order():
    content = (
        "Host: first.example\n"
        "Sitemap: https://site.local/one.xml\n"
        "Host: second.example\n"
        "Sitemap: https://site.local/one.xml\n"
        "User-agent: *\n"
        "Disallow: /private\n"
    )
    parsed = Protego.parse(content)
    text = parsed.to_text()

    assert text == (
        "User-agent: *\n"
        "Disallow: /private\n"
        "\n"
        "Host: first.example\n"
        "Sitemap: https://site.local/one.xml\n"
        "Host: second.example\n"
        "Sitemap: https://site.local/one.xml\n"
    )
    assert_round_trip(content, ["*", "Other"], ["http://example.com/private"])


def test_to_text_does_not_depend_on_the_query_cache():
    content = "User-agent: Foo\nDisallow: /x\nUser-agent: *\nDisallow: /y\n"
    parsed = Protego.parse(content)
    before = parsed.to_text()

    for agent in ["Foo", "Other", "Foo", "*", "Mozilla/5.0"]:
        parsed.can_fetch("http://example.com/x", agent)
        parsed.crawl_delay(agent)
        parsed.request_rate(agent)
        parsed.visit_time(agent)

    assert parsed.to_text() == before


def test_to_text_of_empty_parse_is_empty():
    assert Protego.parse("").to_text() == ""
    assert Protego.parse("# only a comment\n").to_text() == ""
