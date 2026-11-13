from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from protego import Decision, RobotsManager, RobotsRequest, RobotsResponse, RobotsState


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class QueueFetch:
    def __init__(self, *responses: object) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, **kwargs: Any) -> object:
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError(f"unexpected fetch for {url}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _body(rules: str = "User-agent: *\nDisallow: /private\n") -> str:
    return rules


def test_200_is_parsed_and_fresh_cache_is_reused() -> None:
    clock = FakeClock()
    fetch = QueueFetch(RobotsResponse(200, _body(), {"ETag": '"v1"'}))
    manager = RobotsManager(fetch, clock, cache_ttl=100)

    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.DISALLOW
    assert result.allowed is False
    assert result.version == '"v1"'
    assert result.state is RobotsState.FRESH
    assert result.stale is False
    assert result.status == 200
    assert result.revision == 1

    clock.advance(99)
    cached = manager.decision("https://example.com/public", "bot")
    assert cached.decision is Decision.ALLOW
    assert cached.from_cache is True
    assert len(fetch.calls) == 1


def test_304_reuses_the_cached_policy_and_refreshes_its_age() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        RobotsResponse(200, _body(), {"ETag": '"v1"'}),
        RobotsResponse(304, None, {"ETag": '"v1"'}),
    )
    manager = RobotsManager(fetch, clock, cache_ttl=100)

    first = manager.decision("https://example.com/private", "bot")
    assert first.decision is Decision.DISALLOW

    clock.advance(101)
    validated = manager.decision("https://example.com/private", "bot")
    assert validated.decision is Decision.DISALLOW
    assert validated.version == '"v1"'
    assert validated.from_cache is True
    assert validated.stale is False
    assert validated.status == 304
    assert validated.fetched_at == clock.now
    assert fetch.calls[1][0] == "https://example.com/robots.txt"
    assert fetch.calls[1][1]["etag"] == '"v1"'
    assert fetch.calls[1][1]["headers"] == {"If-None-Match": '"v1"'}

    clock.advance(50)
    assert manager.decision("https://example.com/private", "bot").decision is (
        Decision.DISALLOW
    )
    assert len(fetch.calls) == 2


def test_4xx_is_unavailable_and_allows_everything() -> None:
    clock = FakeClock()
    fetch = QueueFetch(RobotsResponse(404, "not found"))
    manager = RobotsManager(fetch, clock, cache_ttl=100)

    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.ALLOW
    assert result.allowed is True
    assert result.state is RobotsState.UNAVAILABLE
    assert result.version is None
    assert result.stale is False
    assert result.status == 404

    clock.advance(50)
    again = manager.decision("https://example.com/private", "bot")
    assert again.decision is Decision.ALLOW
    assert len(fetch.calls) == 1


def test_first_unreachable_is_unknown_not_allowed() -> None:
    clock = FakeClock()
    fetch = QueueFetch(RobotsResponse(503), RobotsResponse(503))
    manager = RobotsManager(fetch, clock)

    first = manager.decision("https://example.com/private", "bot")
    assert first.decision is Decision.UNKNOWN
    assert first.allowed is None
    assert first.state is RobotsState.UNREACHABLE
    assert first.consecutive_failures == 1
    assert not first

    clock.advance(1)
    second = manager.decision("https://example.com/private", "bot")
    assert second.decision is Decision.UNKNOWN
    assert second.allowed is None
    assert second.consecutive_failures == 2


def test_network_error_is_unreachable_and_never_allow() -> None:
    clock = FakeClock()
    fetch = QueueFetch(TimeoutError("timed out"))
    manager = RobotsManager(fetch, clock)

    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.UNKNOWN
    assert result.allowed is None
    assert "TimeoutError" in result.reason


def test_repeated_failures_after_success_keep_the_stale_policy() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        RobotsResponse(200, _body(), {"ETag": '"v1"'}),
        RobotsResponse(503),
        OSError("connection refused"),
        RobotsResponse(200, "User-agent: *\nAllow: /\n", {"ETag": '"v2"'}),
    )
    manager = RobotsManager(fetch, clock, cache_ttl=100)

    assert manager.decision("https://example.com/private", "bot").decision is (
        Decision.DISALLOW
    )
    clock.advance(101)

    first_failure = manager.decision("https://example.com/private", "bot")
    assert first_failure.decision is Decision.DISALLOW
    assert first_failure.policy is not None
    assert first_failure.stale is True
    assert first_failure.version == '"v1"'
    assert first_failure.consecutive_failures == 1

    clock.advance(1)
    second_failure = manager.decision("https://example.com/private", "bot")
    assert second_failure.decision is Decision.DISALLOW
    assert second_failure.stale is True
    assert second_failure.consecutive_failures == 2

    clock.advance(101)
    recovered = manager.decision("https://example.com/private", "bot")
    assert recovered.decision is Decision.ALLOW
    assert recovered.version == '"v2"'
    assert recovered.stale is False
    assert recovered.consecutive_failures == 0
    assert recovered.revision == 2


def test_state_is_isolated_by_scheme_host_and_effective_port() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        RobotsResponse(200, _body(), {"ETag": '"http-default"'}),
        RobotsResponse(200, "User-agent: *\nAllow: /\n", {"ETag": '"http-8080"'}),
        RobotsResponse(200, "User-agent: *\nAllow: /\n", {"ETag": '"https-default"'}),
    )
    manager = RobotsManager(fetch, clock, cache_ttl=100)

    assert manager.decision("http://example.com/private", "bot").decision is (
        Decision.DISALLOW
    )
    assert manager.decision("http://example.com:80/private", "bot").decision is (
        Decision.DISALLOW
    )
    assert len(fetch.calls) == 1

    assert manager.decision("http://example.com:8080/private", "bot").decision is (
        Decision.ALLOW
    )
    assert manager.decision("https://example.com/private", "bot").decision is (
        Decision.ALLOW
    )
    assert [call[0] for call in fetch.calls] == [
        "http://example.com/robots.txt",
        "http://example.com:8080/robots.txt",
        "https://example.com/robots.txt",
    ]

    assert manager.decision("http://example.com:8080/private", "bot").version == (
        '"http-8080"'
    )
    assert manager.decision("https://example.com/private", "bot").version == (
        '"https-default"'
    )


def test_redirects_are_followed_but_cache_keeps_the_original_origin() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        RobotsResponse(
            301,
            headers={"Location": "https://cdn.example.net/robots.txt"},
        ),
        RobotsResponse(
            200,
            _body(),
            {"ETag": '"cdn"'},
            "https://cdn.example.net/robots.txt",
        ),
        RobotsResponse(200, "User-agent: *\nAllow: /\n", {"ETag": '"cdn-origin"'}),
    )
    manager = RobotsManager(fetch, clock, cache_ttl=100, max_redirects=5)

    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.DISALLOW
    assert result.origin == ("https", "example.com", 443)
    assert result.final_url == "https://cdn.example.net/robots.txt"
    assert result.version == '"cdn"'
    assert [call[0] for call in fetch.calls] == [
        "https://example.com/robots.txt",
        "https://cdn.example.net/robots.txt",
    ]

    # The final address does not become a second cache key.  Asking directly
    # for the redirect target fetches its own robots.txt.
    direct = manager.decision("https://cdn.example.net/private", "bot")
    assert direct.decision is Decision.ALLOW
    assert direct.origin == ("https", "cdn.example.net", 443)
    assert fetch.calls[2][0] == "https://cdn.example.net/robots.txt"


def test_redirect_limit_is_unreachable() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        RobotsResponse(301, headers={"Location": "https://example.com/a"}),
        RobotsResponse(301, headers={"Location": "https://example.com/b"}),
        RobotsResponse(301, headers={"Location": "https://example.com/c"}),
    )
    manager = RobotsManager(fetch, clock, max_redirects=2)

    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.UNKNOWN
    assert result.allowed is None
    assert result.state is RobotsState.UNREACHABLE
    assert "redirect limit" in result.reason
    assert len(fetch.calls) == 3


def test_callback_can_receive_a_request_or_a_requests_style_response() -> None:
    clock = FakeClock()
    seen: list[RobotsRequest] = []

    def fetch(request: RobotsRequest) -> object:
        seen.append(request)
        return SimpleNamespace(
            status_code=200,
            text=_body(),
            headers={"ETag": '"requests"'},
            url="https://example.com/robots.txt",
            history=[],
        )

    manager = RobotsManager(fetch, clock)
    result = manager.decision("https://example.com/private", "bot")
    assert isinstance(seen[0], RobotsRequest)
    assert seen[0].url == "https://example.com/robots.txt"
    assert result.decision is Decision.DISALLOW
    assert result.version == '"requests"'


def test_tuple_response_and_missing_fetch_callback() -> None:
    clock = FakeClock()
    fetch = QueueFetch(
        (200, _body(), {"ETag": '"tuple"'}, "https://example.com/robots.txt")
    )
    manager = RobotsManager(fetch=fetch, clock=clock)
    result = manager.decision("https://example.com/private", "bot")
    assert result.decision is Decision.DISALLOW
    assert result.version == '"tuple"'

    empty = RobotsManager(clock=clock)
    unknown = empty.decision("https://example.com/private", "bot")
    assert unknown.decision is Decision.UNKNOWN
    assert unknown.allowed is None


def test_result_can_be_compared_as_a_bool_and_enum() -> None:
    clock = FakeClock()
    manager = RobotsManager(
        QueueFetch(RobotsResponse(200, "User-agent: *\nDisallow: /\n")),
        clock,
    )
    result = manager.decision("https://example.com/private", "bot")
    assert result == False
    assert result == Decision.DISALLOW


def test_invalid_url_is_rejected() -> None:
    manager = RobotsManager(QueueFetch(), FakeClock())
    with pytest.raises(ValueError, match="absolute URL"):
        manager.decision("/relative", "bot")
