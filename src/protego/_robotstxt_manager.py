"""Stateful robots.txt management on top of the Protego parser.

Protego only parses robots.txt content. The fetching rules of RFC 9309
(status code handling, redirects, caching and revalidation, and the
treatment of an origin that is temporarily unreachable) are deliberately
left to each caller, which makes them drift apart. This module centralizes
that logic in one manager.

The manager never performs network I/O itself. Callers inject a fetch
callback that turns a request description into a fetch result, and a clock
that returns the current time as a monotonic number of seconds. Protego
therefore keeps no network client dependency.

State is isolated per origin, i.e. by the scheme, the host and the
effective port of the URL the crawler asked about. A redirect only decides
where the bytes come from: the fetched policy always stays attached to the
origin that initiated the fetch, never to the final address.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from ._protego import Protego

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


# RFC 9309 section 2.3.1.2: a cached robots.txt is revalidated at least once
# every 24 hours.
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60

# How long an origin that answered 4xx stays considered "no robots.txt"
# before another attempt is made. RFC 9309 does not pin this number, so it
# stays short relative to the 24-hour policy lifetime.
DEFAULT_UNAVAILABLE_TTL_SECONDS = 60 * 60

# RFC 9309 section 2.3.1.3: clients follow at most five consecutive
# redirects while resolving a robots.txt.
MAX_REDIRECTS = 5

# Fallback retry window for a 5xx/429 answer or a network failure when the
# response carries no usable Retry-After header.
DEFAULT_RETRY_AFTER_SECONDS = 60 * 60

# Default ports of the schemes that can carry robots.txt state. Explicit
# default ports are normalized away, so http://h:80 and http://h are the same
# origin.
_DEFAULT_PORTS = {"http": 80, "https": 443}


class RobotsStatus(StrEnum):
    """What is currently known about one origin's robots.txt.

    The states encode the fetch and cache rules of RFC 9309
    (sections 2.3.1.2 and 2.3.1.4) explicitly instead of leaving callers to
    infer behavior from raw status codes.
    """

    # Nothing has been fetched for this origin yet.
    UNKNOWN = "unknown"
    # A robots.txt was fetched and parsed successfully.
    FETCHED = "fetched"
    # A conditional request confirmed the cached policy is still current
    # (HTTP 304), so the previous policy is reused.
    REVALIDATED = "revalidated"
    # A 4xx answer (notably 404) marks robots.txt unavailable; the origin
    # is treated as allowing everything.
    UNAVAILABLE = "unavailable"
    # A 5xx/429 answer or a network failure makes robots.txt temporarily
    # unreachable. A previously cached policy, if any, keeps being served.
    TEMPORARILY_UNREACHABLE = "temporarily_unreachable"
    # The robots.txt resolution failed (e.g. more than five redirects),
    # leaving no usable policy.
    ERROR = "error"


class RobotsDecision(StrEnum):
    """The manager's current answer for an origin."""

    # A fetched policy allows the URL, or a 4xx answer means no rules apply.
    ALLOWED = "allowed"
    # A fetched policy disallows the URL.
    DISALLOWED = "disallowed"
    # No policy could be established and none is cached. This is not an
    # allow: it must never be reported as a definitive permit.
    UNKNOWN = "unknown"


class RobotsVersion(StrEnum):
    """Which version of the rules backs the current decision."""

    # The policy comes straight from the latest successful fetch.
    FRESH = "fresh"
    # The policy is served past its revalidation time after an
    # unreachable/failed fetch, as allowed by RFC 9309 section 2.3.1.2.
    STALE = "stale"
    # No robots.txt policy exists (4xx answer or no data yet).
    NONE = "none"


@dataclass(frozen=True, slots=True)
class RobotsFetchRequest:
    """What the fetch callback is asked to retrieve.

    ``url`` always points at the ``/robots.txt`` of the origin currently
    being resolved. ``if_none_match`` and ``if_modified_since`` carry the
    validator stored from a previous successful response and are used for
    conditional revalidation requests; they are ``None`` on the first fetch.
    """

    url: str
    if_none_match: str | None = None
    if_modified_since: str | None = None


@dataclass(frozen=True, slots=True)
class RobotsFetchResult:
    """The outcome of one fetch callback invocation.

    ``status`` is the HTTP status code, or ``None`` when the request never
    reached a response (DNS failure, connection refused, timeout, ...).
    ``body`` holds the robots.txt text for a 200 response and is otherwise
    ignored. ``etag`` and ``last_modified`` are the raw response validator
    header values, kept verbatim for conditional requests.

    For a 3xx redirect, ``location`` carries the raw Location header and is
    resolved relative to the request URL by the manager. For every other
    response ``final_url`` is the address the response ultimately came from
    after redirects. Both fields are informational only: the manager never
    uses either to change the identity of the origin whose state is being
    updated, so a cross-origin redirect cannot overwrite another origin's
    policy.

    ``retry_after`` carries a Retry-After header value (delta seconds or an
    HTTP date) when the server provided one.
    """

    status: int | None
    final_url: str
    body: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    location: str | None = None
    retry_after: str | None = None


@runtime_checkable
class RobotsFetcher(Protocol):
    """Callable signature for the injected HTTP fetch callback."""

    def __call__(self, request: RobotsFetchRequest) -> RobotsFetchResult: ...


@dataclass(slots=True)
class _OriginState:
    """Everything the manager remembers about one origin."""

    origin: str
    parser: Protego | None = None
    status: RobotsStatus = RobotsStatus.UNKNOWN
    # Stored validators for conditional requests.
    etag: str | None = None
    last_modified: str | None = None
    # Time at which the current policy must be revalidated, or until which
    # an unreachable/error state blocks further attempts.
    expires_at: float = 0.0
    # Whether the served parser is past its revalidation time.
    stale: bool = False
    # Number of consecutive failures since the last successful policy; used
    # to distinguish "policy then failures" from "failure from the start".
    consecutive_failures: int = 0
    redirects: int = 0
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class RobotsEvaluation:
    """The manager's answer for one URL.

    ``decision`` is what the caller should act on, ``status`` explains how
    the origin's robots.txt currently stands, ``version`` says which policy
    generation backs the decision and ``stale`` is True when that policy is
    being used past its revalidation time.
    """

    decision: RobotsDecision
    status: RobotsStatus
    version: RobotsVersion
    stale: bool


@dataclass(frozen=True, slots=True)
class RobotsOriginStateView:
    """Read-only snapshot of one origin's cached robots.txt state."""

    origin: str
    status: RobotsStatus
    stale: bool
    expires_at: float
    etag: str | None
    last_modified: str | None
    redirects: int
    consecutive_failures: int
    last_error: str | None
    has_policy: bool


class RobotsTxtManager:
    """Manage robots.txt fetching, caching and decisions per origin.

    One manager holds the state of every origin seen. State is keyed by the
    scheme, host and effective port of the URLs passed in, so the same host
    on two ports or two schemes is handled independently.

    Time is read from the injected ``clock`` (a zero-argument callable
    returning seconds as a float) and HTTP from the injected ``fetcher``.
    With a scripted clock and fetcher the manager advances through states
    without any real waiting or network access.
    """

    def __init__(
        self,
        fetcher: Callable[[RobotsFetchRequest], RobotsFetchResult],
        *,
        clock: Callable[[], float] | None = None,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        unavailable_ttl_seconds: float = DEFAULT_UNAVAILABLE_TTL_SECONDS,
        default_retry_after_seconds: float = DEFAULT_RETRY_AFTER_SECONDS,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        self._fetcher = fetcher
        self._clock = clock if clock is not None else _monotonic_clock
        self._cache_ttl = cache_ttl_seconds
        self._unavailable_ttl = unavailable_ttl_seconds
        self._default_retry_after = default_retry_after_seconds
        self._max_redirects = max_redirects
        self._states: dict[str, _OriginState] = {}

    # ------------------------------------------------------------------ keys

    def origin_key(self, url: str) -> str:
        """Return the scheme/host/effective-port identity of ``url``.

        Default scheme ports are normalized away, so ``http://h:80/`` and
        ``http://h/`` share a state while ``http://h:8080/`` gets its own.
        Only the ``http`` and ``https`` schemes carry robots.txt state per
        RFC 9309 section 2.3.1.1.
        """
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(
                f"robots.txt state only exists for http(s) URLs, got {url!r}"
            )
        host = parts.hostname
        if not host:
            raise ValueError(f"URL has no host: {url!r}")
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"URL has an invalid port: {url!r}") from exc
        if port is None or port == _DEFAULT_PORTS[parts.scheme]:
            return f"{parts.scheme}://{host}"
        return f"{parts.scheme}://{host}:{port}"

    def _get_state(self, url: str) -> _OriginState:
        key = self.origin_key(url)
        state = self._states.get(key)
        if state is None:
            state = _OriginState(origin=key)
            self._states[key] = state
        return state

    # ------------------------------------------------------------ fetching

    def refresh(self, url: str) -> RobotsStatus:
        """Fetch or revalidate the robots.txt of the origin of ``url``.

        Follow the RFC 9309 fetch rules, honoring the cached state and the
        injected clock, and return the resulting :class:`RobotsStatus`.
        A fetch is skipped while the current state is still fresh.
        """
        state = self._get_state(url)
        now = self._clock()

        if self._is_fresh(state, now):
            return state.status

        request = RobotsFetchRequest(
            url=f"{state.origin}/robots.txt",
            if_none_match=state.etag,
            if_modified_since=state.last_modified,
        )
        followed = self._follow_redirects(request)
        if followed is None:
            return self._store_error(state, now)
        result, redirect_count = followed
        state.redirects = redirect_count
        return self._apply_result(state, result, now)

    def _follow_redirects(
        self, request: RobotsFetchRequest
    ) -> tuple[RobotsFetchResult, int] | None:
        """Drive the fetcher through redirects, capped at max_redirects.

        RFC 9309 section 2.3.1.3: at least five consecutive redirects are
        followed, including across origins; each new Location is resolved
        relative to the current URL. Return ``None`` when the chain cannot be
        resolved (too many hops, or a redirect without a Location), leaving
        the caller to record an error state.
        """
        current = request
        hops = 0
        while True:
            result = self._fetcher(current)
            if not _is_redirect(result.status):
                return result, hops
            if hops >= self._max_redirects or not result.location:
                logger.debug(
                    "robots.txt redirect chain could not be resolved at %s "
                    "after %s hop(s)",
                    current.url,
                    hops,
                )
                return None
            next_url = urljoin(current.url, result.location)
            hops += 1
            # Validators belong to the previous response, not to the next
            # hop's potentially different origin.
            current = RobotsFetchRequest(url=next_url)

    def _apply_result(
        self, state: _OriginState, result: RobotsFetchResult, now: float
    ) -> RobotsStatus:
        status = result.status

        if status is not None and 200 <= status < 300:
            return self._store_fetched(state, result, now)
        if status == 304:
            return self._store_revalidated(state, result, now)
        # RFC 9309 section 2.3.1.2 groups 429 with 5xx as a temporary,
        # retryable condition even though it is numerically a 4xx.
        if status == 429 or status is None or (status is not None and status >= 500):
            return self._store_unreachable(
                state, now, retry_after=result.retry_after, status=status
            )
        if status is not None and 400 <= status < 500:
            return self._store_unavailable(state, now)
        # Any other status (1xx, non-standard 3xx other than 304, ...) gives
        # no usable policy and is treated as a temporary failure too.
        return self._store_unreachable(
            state, now, retry_after=result.retry_after, status=status
        )

    # --------------------------------------------------------- transitions

    def _store_fetched(
        self, state: _OriginState, result: RobotsFetchResult, now: float
    ) -> RobotsStatus:
        # RFC 9309 section 2.3.1.2: a 200 response replaces any cached
        # robots.txt, even an empty or unparseable one.
        body = result.body if result.body is not None else ""
        state.parser = Protego.parse(body)
        state.etag = result.etag
        state.last_modified = result.last_modified
        state.expires_at = now + self._cache_ttl
        state.stale = False
        state.consecutive_failures = 0
        state.last_error = None
        state.status = RobotsStatus.FETCHED
        return state.status

    def _store_revalidated(
        self, state: _OriginState, result: RobotsFetchResult, now: float
    ) -> RobotsStatus:
        # RFC 9309 section 2.3.1.2: a 304 confirms the cached robots.txt is
        # still current, so it is reused rather than re-parsed. Without a
        # cached policy a 304 makes no sense and is treated as a failure.
        if state.parser is None:
            return self._store_unreachable(
                state, now, retry_after=result.retry_after, status=304
            )
        # Refresh validators if the server restated them.
        if result.etag is not None:
            state.etag = result.etag
        if result.last_modified is not None:
            state.last_modified = result.last_modified
        state.expires_at = now + self._cache_ttl
        state.stale = False
        state.consecutive_failures = 0
        state.last_error = None
        state.status = RobotsStatus.REVALIDATED
        return state.status

    def _store_unavailable(self, state: _OriginState, now: float) -> RobotsStatus:
        # RFC 9309 section 2.3.1.2: any 4xx (404, 401, 403, ...) means no
        # robots.txt is available, so the origin is fully crawlable. Any
        # earlier policy is discarded.
        state.parser = None
        state.etag = None
        state.last_modified = None
        state.stale = False
        state.consecutive_failures = 0
        state.last_error = None
        state.expires_at = now + self._unavailable_ttl
        state.status = RobotsStatus.UNAVAILABLE
        return state.status

    def _store_unreachable(
        self,
        state: _OriginState,
        now: float,
        *,
        retry_after: str | None,
        status: int | None,
    ) -> RobotsStatus:
        # RFC 9309 section 2.3.1.2: 5xx/429 or an unreachable server is a
        # temporary condition. A cached robots.txt keeps being served, marked
        # stale; without one there is no policy at all, which is distinct
        # from an explicit allow-all.
        state.consecutive_failures += 1
        state.last_error = "network error" if status is None else f"HTTP {status}"
        if state.parser is not None:
            state.stale = True
        state.expires_at = now + self._retry_delay(retry_after, now)
        state.status = RobotsStatus.TEMPORARILY_UNREACHABLE
        return state.status

    def _retry_delay(self, retry_after: str | None, now: float) -> float:
        # Prefer the server's Retry-After when it is usable, otherwise fall
        # back to the configured window.
        if retry_after is not None:
            seconds = _parse_retry_after(retry_after, now)
            if seconds is not None and seconds >= 0:
                return seconds
        return self._default_retry_after

    def _store_error(self, state: _OriginState, now: float) -> RobotsStatus:
        # A redirect chain that cannot be resolved establishes no policy. A
        # previously cached one, if any, is kept and marked stale rather than
        # silently dropped.
        state.consecutive_failures += 1
        state.last_error = f"redirect chain exceeded {self._max_redirects} hops"
        if state.parser is not None:
            state.stale = True
        state.expires_at = now + self._default_retry_after
        state.status = RobotsStatus.ERROR
        return state.status

    # ------------------------------------------------------------ decisions

    def evaluate(self, url: str, user_agent: str) -> RobotsEvaluation:
        """Return the current decision for ``url`` without fetching.

        The result carries the :class:`RobotsDecision`, the underlying
        :class:`RobotsStatus`, the :class:`RobotsVersion` of the policy in
        force and whether that policy is being used past its revalidation
        time. An origin that was never reached and has no cached policy
        reports :data:`RobotsDecision.UNKNOWN`, never an allow.
        """
        state = self._get_state(url)
        now = self._clock()
        stale = state.stale or (
            state.parser is not None and not self._is_fresh(state, now)
        )

        if state.parser is not None:
            # A fetched policy stays in force even while the origin is
            # temporarily unreachable or in an error state: RFC 9309 keeps
            # serving the cached robots.txt, flagged as stale, rather than
            # withdrawing every decision.
            allowed = state.parser.can_fetch(url, user_agent)
            decision = (
                RobotsDecision.ALLOWED if allowed else RobotsDecision.DISALLOWED
            )
            version = RobotsVersion.STALE if stale else RobotsVersion.FRESH
        elif state.status == RobotsStatus.UNAVAILABLE:
            # A 4xx answer means no robots.txt exists, so everything is
            # crawlable and no policy version is in force.
            decision = RobotsDecision.ALLOWED
            version = RobotsVersion.NONE
        else:
            # Never contacted, or unreachable/error with nothing cached: the
            # absence of a policy is not an allow, so report UNKNOWN rather
            # than disguising it as a definitive permit.
            decision = RobotsDecision.UNKNOWN
            version = RobotsVersion.NONE

        return RobotsEvaluation(
            decision=decision,
            status=state.status,
            version=version,
            stale=stale,
        )

    def can_fetch(self, url: str, user_agent: str) -> bool:
        """Return True only when a known policy explicitly allows ``url``.

        This deliberately returns False for :data:`RobotsDecision.UNKNOWN`,
        so an origin whose robots.txt was never established is never silently
        treated as crawlable. Callers that want to distinguish "disallowed"
        from "not yet known" should use :meth:`evaluate`.
        """
        return self.evaluate(url, user_agent).decision is RobotsDecision.ALLOWED

    def get_state(self, url: str) -> RobotsOriginStateView:
        """Return a read-only snapshot of the origin's cached state."""
        state = self._get_state(url)
        return RobotsOriginStateView(
            origin=state.origin,
            status=state.status,
            stale=state.stale,
            expires_at=state.expires_at,
            etag=state.etag,
            last_modified=state.last_modified,
            redirects=state.redirects,
            consecutive_failures=state.consecutive_failures,
            last_error=state.last_error,
            has_policy=state.parser is not None,
        )

    # ------------------------------------------------------------- helpers

    def _is_fresh(self, state: _OriginState, now: float) -> bool:
        if state.status is RobotsStatus.UNKNOWN:
            return False
        return now < state.expires_at


def _monotonic_clock() -> float:
    return time.monotonic()


def _is_redirect(status: int | None) -> bool:
    return status in (301, 302, 303, 307, 308)


def _parse_retry_after(value: str, now: float) -> float | None:
    """Parse a Retry-After header value into a delay in seconds."""
    value = value.strip()
    if not value:
        return None
    try:
        return float(int(value))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if retry_at is None:
        return None
    return retry_at.timestamp() - now
