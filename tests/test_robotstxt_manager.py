"""Tests for the stateful RFC 9309 robots.txt manager.

The clock and the HTTP fetch callback are both scripted, so time advances
and responses arrive without any real waiting or network I/O.
"""

from __future__ import annotations

from email.utils import parsedate_to_datetime
from typing import Any

import pytest

from protego import (
    RobotsDecision,
    RobotsFetcher,
    RobotsFetchRequest,
    RobotsFetchResult,
    RobotsStatus,
    RobotsTxtManager,
    RobotsVersion,
)


class ScriptedClock:
    """A controllable clock returning seconds as a float."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ScriptedFetcher:
    """Fetch callback driven by a queue of scripted responses.

    Each response is either a :class:`RobotsFetchResult` or an exception the
    callback should raise, simulating a client that cannot return a result.
    """

    def __init__(self, *responses: RobotsFetchResult | type[Exception]) -> None:
        self._responses = list(responses)
        self.requests: list[RobotsFetchRequest] = []

    def __call__(self, request: RobotsFetchRequest) -> RobotsFetchResult:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("unexpected fetch request")
        response = self._responses.pop(0)
        if isinstance(response, type) and issubclass(response, Exception):
            raise response("scripted network failure")
        return response

    @property
    def exhausted(self) -> bool:
        return not self._responses


def robots(body: str, **kwargs: Any) -> RobotsFetchResult:
    return RobotsFetchResult(
        status=200,
        final_url="https://example.com/robots.txt",
        body=body,
        **kwargs,
    )


def result(status: int | None, **kwargs: Any) -> RobotsFetchResult:
    return RobotsFetchResult(
        status=status,
        final_url="https://example.com/robots.txt",
        **kwargs,
    )


DISALLOW_PRIVATE = "User-agent: *\nDisallow: /private\n"


# --------------------------------------------------------------------- basics


class TestOriginIsolation:
    def test_origin_key_scheme_host_and_effective_port(self):
        fetcher = ScriptedFetcher()
        manager = RobotsTxtManager(fetcher, clock=ScriptedClock())

        assert manager.origin_key("https://example.com/path") == "https://example.com"
        assert manager.origin_key("http://example.com:80/path") == "http://example.com"
        assert manager.origin_key("https://example.com:443/") == "https://example.com"
        assert (
            manager.origin_key("http://example.com:8080/")
            == "http://example.com:8080"
        )

    @pytest.mark.parametrize(
        "url_a",
        [
            "http://example.com/",
            "https://example.com/",
            "http://example.com:8080/",
            "https://example.com:8443/",
        ],
    )
    def test_different_origins_keep_independent_state(self, url_a):
        url_b = "https://other.example/"
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE),
            robots("User-agent: *\nDisallow: /other\n"),
        )
        manager = RobotsTxtManager(fetcher, clock=clock)

        manager.refresh(url_a)
        manager.refresh(url_b)

        assert not manager.can_fetch(url_a + "private", "bot")
        assert manager.can_fetch(url_a + "other", "bot")
        assert manager.can_fetch(url_b + "private", "bot")
        assert not manager.can_fetch(url_b + "other", "bot")
        assert fetcher.exhausted

    def test_two_ports_on_same_host_are_separate_origins(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots("User-agent: *\nDisallow: /a\n"),
            robots("User-agent: *\nDisallow: /b\n"),
        )
        manager = RobotsTxtManager(fetcher, clock=clock)

        manager.refresh("http://host.local:8000/")
        manager.refresh("http://host.local:9000/")

        assert not manager.can_fetch("http://host.local:8000/a", "bot")
        assert manager.can_fetch("http://host.local:8000/b", "bot")
        assert manager.can_fetch("http://host.local:9000/a", "bot")
        assert not manager.can_fetch("http://host.local:9000/b", "bot")

    def test_non_http_scheme_is_rejected(self):
        manager = RobotsTxtManager(ScriptedFetcher(), clock=ScriptedClock())
        with pytest.raises(ValueError, match="only exists for http"):
            manager.origin_key("ftp://example.com/robots.txt")

    def test_invalid_port_is_rejected(self):
        manager = RobotsTxtManager(ScriptedFetcher(), clock=ScriptedClock())
        with pytest.raises(ValueError, match="invalid port"):
            manager.origin_key("http://example.com:not-a-port/")

    def test_default_port_variants_share_state_and_normalized_request_url(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE))
        manager = RobotsTxtManager(fetcher, clock=clock)

        manager.refresh("https://example.com:443/page")
        manager.refresh("https://example.com/other")

        assert len(fetcher.requests) == 1
        assert fetcher.requests[0].url == "https://example.com/robots.txt"


class TestSuccessfulFetch:
    def test_200_parses_policy_and_returns_fresh_decision(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE, etag='"v1"'))
        manager = RobotsTxtManager(fetcher, clock=clock)

        status = manager.refresh("https://example.com/")
        assert status is RobotsStatus.FETCHED

        evaluation = manager.evaluate("https://example.com/private", "bot")
        assert evaluation.decision is RobotsDecision.DISALLOWED
        assert evaluation.status is RobotsStatus.FETCHED
        assert evaluation.version is RobotsVersion.FRESH
        assert evaluation.stale is False

        assert manager.can_fetch("https://example.com/public", "bot") is True
        assert manager.can_fetch("https://example.com/private", "bot") is False

        snapshot = manager.get_state("https://example.com/")
        assert snapshot.has_policy is True
        assert snapshot.etag == '"v1"'
        assert snapshot.consecutive_failures == 0

    def test_refresh_is_skipped_while_state_is_fresh(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE))
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=100)

        manager.refresh("https://example.com/")
        clock.advance(50)
        status = manager.refresh("https://example.com/")

        assert status is RobotsStatus.FETCHED
        assert len(fetcher.requests) == 1

    def test_expired_policy_triggers_conditional_request_with_validators(self):
        clock = ScriptedClock()
        last_modified = "Wed, 21 Oct 2026 07:28:00 GMT"
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE, etag='"et"', last_modified=last_modified)
        )
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=100)
        manager.refresh("https://example.com/")

        clock.advance(101)
        fetcher._responses.append(result(304))
        status = manager.refresh("https://example.com/")

        assert status is RobotsStatus.REVALIDATED
        conditional = fetcher.requests[-1]
        assert conditional.if_none_match == '"et"'
        assert conditional.if_modified_since == "Wed, 21 Oct 2026 07:28:00 GMT"

        evaluation = manager.evaluate("https://example.com/private", "bot")
        assert evaluation.decision is RobotsDecision.DISALLOWED
        assert evaluation.version is RobotsVersion.FRESH
        assert evaluation.stale is False

    def test_304_updates_stored_validators(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE, etag='"v1"'),
            result(304, etag='"v2"'),
        )
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=10)
        manager.refresh("https://example.com/")
        clock.advance(11)
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").etag == '"v2"'

    def test_200_replaces_stale_policy_and_validators(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots("User-agent: *\nDisallow: /old\n", etag='"v1"'),
            robots("User-agent: *\nDisallow: /new\n", etag='"v2"'),
        )
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=10)
        manager.refresh("https://example.com/")
        clock.advance(11)
        manager.refresh("https://example.com/")

        assert manager.can_fetch("https://example.com/old", "bot") is True
        assert manager.can_fetch("https://example.com/new", "bot") is False
        assert manager.get_state("https://example.com/").etag == '"v2"'


class TestClientErrors:
    @pytest.mark.parametrize("code", [401, 403, 404, 410, 418])
    def test_4xx_means_no_robots_txt_and_allows_everything(self, code):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(code))
        manager = RobotsTxtManager(fetcher, clock=clock)

        assert manager.refresh("https://example.com/") is RobotsStatus.UNAVAILABLE
        evaluation = manager.evaluate("https://example.com/anything", "bot")
        assert evaluation.decision is RobotsDecision.ALLOWED
        assert evaluation.version is RobotsVersion.NONE
        assert manager.can_fetch("https://example.com/anything", "bot") is True
        assert manager.get_state("https://example.com/").has_policy is False

    def test_4xx_discards_a_previously_cached_policy(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE),
            result(404),
        )
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=10)
        manager.refresh("https://example.com/")
        assert manager.can_fetch("https://example.com/private", "bot") is False

        clock.advance(11)
        manager.refresh("https://example.com/")
        assert manager.can_fetch("https://example.com/private", "bot") is True
        assert manager.get_state("https://example.com/").etag is None

    def test_unavailable_state_is_cached_for_its_ttl(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(404))
        manager = RobotsTxtManager(fetcher, clock=clock, unavailable_ttl_seconds=30)
        manager.refresh("https://example.com/")
        clock.advance(29)
        manager.refresh("https://example.com/")
        assert len(fetcher.requests) == 1

        clock.advance(2)
        fetcher._responses.append(robots(DISALLOW_PRIVATE))
        manager.refresh("https://example.com/")
        assert len(fetcher.requests) == 2


class TestTemporaryUnreachability:
    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    def test_5xx_without_policy_is_unknown_not_an_allow(self, code):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(code))
        manager = RobotsTxtManager(fetcher, clock=clock)

        status = manager.refresh("https://example.com/")
        assert status is RobotsStatus.TEMPORARILY_UNREACHABLE

        evaluation = manager.evaluate("https://example.com/whatever", "bot")
        assert evaluation.decision is RobotsDecision.UNKNOWN
        assert evaluation.version is RobotsVersion.NONE
        assert evaluation.stale is False
        # An unknown origin must never look like a definitive allow.
        assert manager.can_fetch("https://example.com/whatever", "bot") is False

    def test_network_failure_without_policy_is_unknown(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(ConnectionError)
        manager = RobotsTxtManager(fetcher, clock=clock)

        with pytest.raises(ConnectionError, match="scripted network failure"):
            manager.refresh("https://example.com/")
        evaluation = manager.evaluate("https://example.com/whatever", "bot")
        assert evaluation.decision is RobotsDecision.UNKNOWN

    def test_never_contacted_origin_is_unknown(self):
        manager = RobotsTxtManager(ScriptedFetcher(), clock=ScriptedClock())
        evaluation = manager.evaluate("https://brand-new.example/x", "bot")
        assert evaluation.status is RobotsStatus.UNKNOWN
        assert evaluation.decision is RobotsDecision.UNKNOWN
        assert evaluation.version is RobotsVersion.NONE
        assert manager.can_fetch("https://brand-new.example/x", "bot") is False

    def test_policy_then_repeated_failures_keeps_serving_stale_policy(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE, etag='"v1"'),
            result(503, retry_after="100"),
            result(None),
            result(500),
        )
        manager = RobotsTxtManager(
            fetcher,
            clock=clock,
            cache_ttl_seconds=50,
            default_retry_after_seconds=25,
        )

        manager.refresh("https://example.com/")
        clock.advance(51)
        assert (
            manager.refresh("https://example.com/")
            is RobotsStatus.TEMPORARILY_UNREACHABLE
        )
        snapshot = manager.get_state("https://example.com/")
        assert snapshot.consecutive_failures == 1
        assert snapshot.stale is True
        assert snapshot.last_error == "HTTP 503"

        stale = manager.evaluate("https://example.com/private", "bot")
        assert stale.decision is RobotsDecision.DISALLOWED
        assert stale.version is RobotsVersion.STALE
        assert stale.stale is True
        assert manager.can_fetch("https://example.com/private", "bot") is False
        assert manager.can_fetch("https://example.com/public", "bot") is True

        # The Retry-After window blocks another attempt while it lasts.
        clock.advance(99)
        assert (
            manager.refresh("https://example.com/")
            is RobotsStatus.TEMPORARILY_UNREACHABLE
        )
        assert len(fetcher.requests) == 2

        clock.advance(2)
        manager.refresh("https://example.com/")  # network failure
        clock.advance(26)
        manager.refresh("https://example.com/")  # 500
        assert manager.get_state("https://example.com/").consecutive_failures == 3
        # The cached policy still governs after every failure.
        assert manager.can_fetch("https://example.com/private", "bot") is False

    def test_failure_from_the_start_never_turns_into_an_allow(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            result(503),
            result(None),
        )
        manager = RobotsTxtManager(fetcher, clock=clock, default_retry_after_seconds=10)

        manager.refresh("https://example.com/")
        clock.advance(11)
        manager.refresh("https://example.com/")

        snapshot = manager.get_state("https://example.com/")
        assert snapshot.consecutive_failures == 2
        assert snapshot.has_policy is False
        evaluation = manager.evaluate("https://example.com/x", "bot")
        assert evaluation.decision is RobotsDecision.UNKNOWN
        assert manager.can_fetch("https://example.com/x", "bot") is False

    def test_recovery_after_failures_restores_fresh_policy(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE),
            result(503),
            robots("User-agent: *\nDisallow: /other\n"),
        )
        manager = RobotsTxtManager(
            fetcher,
            clock=clock,
            cache_ttl_seconds=10,
            default_retry_after_seconds=10,
        )
        manager.refresh("https://example.com/")
        clock.advance(11)
        manager.refresh("https://example.com/")
        assert manager.evaluate("https://example.com/private", "bot").stale is True

        clock.advance(11)
        status = manager.refresh("https://example.com/")
        assert status is RobotsStatus.FETCHED
        recovered = manager.evaluate("https://example.com/other", "bot")
        assert recovered.version is RobotsVersion.FRESH
        assert recovered.stale is False
        snapshot = manager.get_state("https://example.com/")
        assert snapshot.consecutive_failures == 0
        assert snapshot.last_error is None


class TestRetryAfter:
    def test_delta_seconds_retry_after_sets_retry_window(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(503, retry_after="42"))
        manager = RobotsTxtManager(
            fetcher,
            clock=clock,
            default_retry_after_seconds=1000,
        )
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").expires_at == 42

    def test_http_date_retry_after_is_measured_from_injected_clock(self):
        clock = ScriptedClock(start=1_000.0)
        retry_after = "Wed, 21 Oct 2026 07:28:40 GMT"
        fetcher = ScriptedFetcher(result(503, retry_after=retry_after))
        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://example.com/")

        target = parsedate_to_datetime(retry_after).timestamp()
        assert manager.get_state("https://example.com/").expires_at == target

    def test_unusable_retry_after_falls_back_to_default(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(503, retry_after="soon"))
        manager = RobotsTxtManager(fetcher, clock=clock, default_retry_after_seconds=77)
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").expires_at == 77


class TestRedirects:
    def test_redirect_is_followed_and_policy_binds_to_original_origin(self):
        clock = ScriptedClock()

        def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
            if request.url == "https://shop.example/robots.txt":
                return RobotsFetchResult(
                    302, request.url, location="https://cdn.example.net/r.txt"
                )
            return RobotsFetchResult(200, request.url, body=DISALLOW_PRIVATE)

        manager = RobotsTxtManager(fetcher, clock=clock)
        status = manager.refresh("https://shop.example/")
        assert status is RobotsStatus.FETCHED

        snapshot = manager.get_state("https://shop.example/")
        assert snapshot.redirects == 1
        assert snapshot.has_policy is True
        # The final address never hijacks another origin's identity.
        assert (
            manager.get_state("https://cdn.example.net/").status
            is RobotsStatus.UNKNOWN
        )
        assert manager.can_fetch("https://shop.example/private", "bot") is False

    def test_relative_redirect_location_is_resolved(self):
        clock = ScriptedClock()
        responses = iter(
            [
                RobotsFetchResult(301, "https://example.com/robots.txt", location="/r"),
                RobotsFetchResult(200, "https://example.com/r", body=DISALLOW_PRIVATE),
            ]
        )
        manager = RobotsTxtManager(lambda request: next(responses), clock=clock)
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").redirects == 1
        assert manager.can_fetch("https://example.com/private", "bot") is False

    def test_five_redirects_are_followed_but_the_sixth_fails(self):
        clock = ScriptedClock()
        seen: list[str] = []

        def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
            seen.append(request.url)
            if len(seen) <= 6:
                return RobotsFetchResult(307, request.url, location=f"/r{len(seen)}")
            return RobotsFetchResult(200, request.url, body=DISALLOW_PRIVATE)

        manager = RobotsTxtManager(fetcher, clock=clock, max_redirects=5)
        assert manager.refresh("https://example.com/") is RobotsStatus.ERROR
        snapshot = manager.get_state("https://example.com/")
        assert snapshot.has_policy is False
        assert snapshot.last_error is not None
        assert (
            manager.evaluate("https://example.com/x", "bot").decision
            is RobotsDecision.UNKNOWN
        )

    def test_redirect_without_location_is_an_error(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(302))
        manager = RobotsTxtManager(fetcher, clock=clock)
        assert manager.refresh("https://example.com/") is RobotsStatus.ERROR

    def test_redirect_error_keeps_a_previously_cached_policy_stale(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE),
            result(302),
        )
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=10)
        manager.refresh("https://example.com/")
        clock.advance(11)
        assert manager.refresh("https://example.com/") is RobotsStatus.ERROR
        evaluation = manager.evaluate("https://example.com/private", "bot")
        assert evaluation.status is RobotsStatus.ERROR
        assert evaluation.version is RobotsVersion.STALE
        assert evaluation.decision is RobotsDecision.DISALLOWED

    def test_redirect_validators_are_not_forwarded_to_next_hop(self):
        clock = ScriptedClock()
        seen: list[RobotsFetchRequest] = []

        def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
            seen.append(request)
            if len(seen) == 1:
                return RobotsFetchResult(
                    302, request.url, location="https://other.example/robots.txt"
                )
            return RobotsFetchResult(200, request.url, body=DISALLOW_PRIVATE)

        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://example.com/")
        assert seen[1].if_none_match is None
        assert seen[1].if_modified_since is None

    def test_redirect_to_404_marks_only_the_original_origin_unavailable(self):
        clock = ScriptedClock()

        def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
            if request.url == "https://a.example/robots.txt":
                return RobotsFetchResult(
                    302, request.url, location="https://b.example/robots.txt"
                )
            return RobotsFetchResult(404, request.url)

        manager = RobotsTxtManager(fetcher, clock=clock)
        status = manager.refresh("https://a.example/")
        assert status is RobotsStatus.UNAVAILABLE
        assert manager.get_state("https://a.example/").redirects == 1
        assert (
            manager.get_state("https://b.example/").status
            is RobotsStatus.UNKNOWN
        )
        assert manager.can_fetch("https://a.example/anything", "bot") is True


class TestContract:
    def test_fetcher_protocol_is_satisfied_by_callables(self):
        def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
            return RobotsFetchResult(200, request.url, body="")

        assert isinstance(fetcher, RobotsFetcher)

    def test_default_clock_advances_without_injection(self):
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE))
        manager = RobotsTxtManager(fetcher, cache_ttl_seconds=10)
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").expires_at > 0

    def test_final_url_does_not_change_origin_identity(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            RobotsFetchResult(
                200,
                "https://evil.example.net/robots.txt",
                body="User-agent: *\nDisallow: /\n",
            )
        )
        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://good.example/")

        assert manager.origin_key("https://good.example/") == "https://good.example"
        snapshot = manager.get_state("https://good.example/")
        assert snapshot.origin == "https://good.example"
        assert (
            manager.get_state("https://evil.example.net/").status
            is RobotsStatus.UNKNOWN
        )

    def test_state_snapshot_is_a_read_only_view(self):
        import dataclasses

        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE))
        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://example.com/")
        snapshot = manager.get_state("https://example.com/")
        assert dataclasses.is_dataclass(snapshot)
        with pytest.raises(dataclasses.FrozenInstanceError):
            snapshot.stale = True  # type: ignore[misc]

    def test_304_without_cached_policy_is_treated_as_failure(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(result(304))
        manager = RobotsTxtManager(fetcher, clock=clock)
        assert (
            manager.refresh("https://example.com/")
            is RobotsStatus.TEMPORARILY_UNREACHABLE
        )
        assert (
            manager.evaluate("https://example.com/x", "bot").decision
            is RobotsDecision.UNKNOWN
        )

    def test_empty_200_body_allows_everything(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(""))
        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://example.com/")
        evaluation = manager.evaluate("https://example.com/anything", "bot")
        assert evaluation.status is RobotsStatus.FETCHED
        assert evaluation.decision is RobotsDecision.ALLOWED


class TestStatusAndVersionEnums:
    def test_enums_carry_stable_string_values(self):
        assert RobotsStatus.FETCHED.value == "fetched"
        assert RobotsStatus.UNAVAILABLE.value == "unavailable"
        assert RobotsDecision.UNKNOWN.value == "unknown"
        assert RobotsVersion.STALE.value == "stale"

    def test_status_isolated_per_scheme(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(
            robots(DISALLOW_PRIVATE),
            RobotsFetchResult(404, "http://example.com/robots.txt"),
        )
        manager = RobotsTxtManager(fetcher, clock=clock)
        manager.refresh("https://example.com/")
        manager.refresh("http://example.com/")

        assert not manager.can_fetch("https://example.com/private", "bot")
        assert manager.can_fetch("http://example.com/private", "bot")
        assert (
            manager.get_state("https://example.com/").status
            is RobotsStatus.FETCHED
        )
        assert (
            manager.get_state("http://example.com/").status
            is RobotsStatus.UNAVAILABLE
        )


class TestDefaults:
    def test_rfc_constants(self):
        from protego._robotstxt_manager import (
            DEFAULT_CACHE_TTL_SECONDS,
            DEFAULT_RETRY_AFTER_SECONDS,
            DEFAULT_UNAVAILABLE_TTL_SECONDS,
            MAX_REDIRECTS,
        )

        assert DEFAULT_CACHE_TTL_SECONDS == 24 * 60 * 60
        assert MAX_REDIRECTS == 5
        assert DEFAULT_UNAVAILABLE_TTL_SECONDS == 60 * 60
        assert DEFAULT_RETRY_AFTER_SECONDS == 60 * 60

    def test_custom_ttls_are_respected(self):
        clock = ScriptedClock()
        fetcher = ScriptedFetcher(robots(DISALLOW_PRIVATE))
        manager = RobotsTxtManager(fetcher, clock=clock, cache_ttl_seconds=7)
        manager.refresh("https://example.com/")
        assert manager.get_state("https://example.com/").expires_at == 7
