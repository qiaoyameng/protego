"""Fetching, caching, and access decisions for ``robots.txt`` files.

Protego only parses ``robots.txt``.  This module adds the HTTP side as an
independent, dependency-free manager: the caller supplies the network
callback and the clock, so the manager never imports an HTTP client and tests
can advance time without sleeping.
"""

from __future__ import annotations

import inspect
import logging
import time as _time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from ._protego import Protego

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 24 * 60 * 60
DEFAULT_MAX_REDIRECTS = 5

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


class Decision(StrEnum):
    """The effective access decision for a URL."""

    ALLOW = "allow"
    DISALLOW = "disallow"
    UNKNOWN = "unknown"


class RobotsState(StrEnum):
    """The state backing the current decision."""

    UNKNOWN = "unknown"
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    UNREACHABLE = "unreachable"


class RobotsResponse:
    """The response returned by a fetch callback.

    Only ``status`` is required.  The class is also a convenient result type
    for callbacks; the manager accepts requests-style objects, mappings, and
    tuples as well.
    """

    __slots__ = (
        "content",
        "final_url",
        "headers",
        "history",
        "redirect_count",
        "status",
        "version",
    )

    def __init__(  # noqa: PLR0917
        self,
        status: int | None = None,
        content: str | bytes | None = None,
        headers: Mapping[str, str] | None = None,
        final_url: str | None = None,
        redirect_count: int | None = None,
        history: Sequence[str] | None = None,
        *,
        status_code: int | None = None,
        text: str | None = None,
        body: str | bytes | None = None,
        url: str | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        location: str | None = None,
        version: str | None = None,
        redirected_url: str | None = None,
    ) -> None:
        if status is None:
            status = status_code
        if content is None:
            content = text if text is not None else body
        if final_url is None:
            final_url = redirected_url
        if final_url is None:
            final_url = url
        self.status = status
        self.content = content
        self.headers = dict(headers or {})
        if etag is not None and "ETag" not in self.headers:
            self.headers["ETag"] = etag
        if last_modified is not None and "Last-Modified" not in self.headers:
            self.headers["Last-Modified"] = last_modified
        if location is not None and "Location" not in self.headers:
            self.headers["Location"] = location
        self.final_url = final_url
        self.redirect_count = redirect_count
        self.history = tuple(history or ())
        self.version = version

    @property
    def status_code(self) -> int | None:
        return self.status

    @property
    def text(self) -> str:
        return _decode_content(self.content)

    @property
    def body(self) -> str | bytes | None:
        return self.content

    @property
    def url(self) -> str | None:
        return self.final_url

    @property
    def redirected_url(self) -> str | None:
        return self.final_url

    @property
    def redirects(self) -> int:
        return self.redirect_count or len(self.history)

    @property
    def etag(self) -> str | None:
        return _header_value(self.headers, "ETag")

    @property
    def last_modified(self) -> str | None:
        return _header_value(self.headers, "Last-Modified")

    @property
    def location(self) -> str | None:
        return _header_value(self.headers, "Location")

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def __repr__(self) -> str:
        return (
            f"RobotsResponse(status={self.status!r}, final_url={self.final_url!r}, "
            f"redirect_count={self.redirect_count!r})"
        )


@dataclass(frozen=True, slots=True)
class RobotsRequest:
    """A request passed to a fetch callback.

    ``etag`` and ``last_modified`` are the validators from the cached policy
    and should be sent as ``If-None-Match`` and ``If-Modified-Since``.
    """

    url: str
    etag: str | None = None
    last_modified: str | None = None
    redirects: int = 0

    @property
    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.etag:
            headers["If-None-Match"] = self.etag
        if self.last_modified:
            headers["If-Modified-Since"] = self.last_modified
        return headers

    @property
    def if_none_match(self) -> str | None:
        return self.etag

    @property
    def if_modified_since(self) -> str | None:
        return self.last_modified


@dataclass(frozen=True, slots=True, eq=False)
class RobotsDecision:
    """The current decision and the metadata used to reach it."""

    decision: Decision
    version: str | None = None
    stale: bool = False
    state: RobotsState = RobotsState.UNKNOWN
    policy: Protego | None = None
    origin: tuple[str, str, int] | None = None
    robots_url: str = ""
    target_url: str | None = None
    final_url: str | None = None
    status: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    fetched_at: float | None = None
    checked_at: float = 0.0
    from_cache: bool = False
    fallback: bool = False
    consecutive_failures: int = 0
    revision: int = 0
    reason: str = ""

    @property
    def allowed(self) -> bool | None:
        """``True``/``False`` when known, or ``None`` when undetermined."""
        if self.decision is Decision.ALLOW:
            return True
        if self.decision is Decision.DISALLOW:
            return False
        return None

    @property
    def known(self) -> bool:
        return self.decision is not Decision.UNKNOWN

    @property
    def unknown(self) -> bool:
        return self.decision is Decision.UNKNOWN

    @property
    def used_stale_policy(self) -> bool:
        return self.stale

    @property
    def used_stale(self) -> bool:
        return self.stale

    @property
    def is_stale(self) -> bool:
        return self.stale

    @property
    def expired(self) -> bool:
        return self.stale

    @property
    def policy_version(self) -> str | None:
        return self.version

    @property
    def version_used(self) -> str | None:
        return self.version

    @property
    def content_version(self) -> int:
        return self.revision

    @property
    def cache_hit(self) -> bool:
        return self.from_cache

    @property
    def source(self) -> RobotsState:
        return self.state

    @property
    def cache_state(self) -> RobotsState:
        return self.state

    @property
    def allow(self) -> bool | None:
        return self.allowed

    @property
    def permitted(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def is_allowed(self) -> bool | None:
        return self.allowed

    @property
    def is_unknown(self) -> bool:
        return self.unknown

    @property
    def outcome(self) -> Decision:
        return self.decision

    @property
    def result(self) -> Decision:
        return self.decision

    @property
    def verdict(self) -> Decision:
        return self.decision

    @property
    def parser(self) -> Protego | None:
        return self.policy

    def can_fetch(self, url: str, user_agent: str = "*") -> bool | None:
        """Return whether *url* is allowed, or ``None`` when undetermined."""
        if self.policy is None:
            return self.allowed
        return self.policy.can_fetch(url, user_agent)

    def crawl_delay(self, user_agent: str) -> float | None:
        if self.policy is None:
            return None
        return self.policy.crawl_delay(user_agent)

    def request_rate(self, user_agent: str) -> Any:
        if self.policy is None:
            return None
        return self.policy.request_rate(user_agent)

    def visit_time(self, user_agent: str) -> Any:
        if self.policy is None:
            return None
        return self.policy.visit_time(user_agent)

    @property
    def sitemaps(self) -> Any:
        if self.policy is None:
            return iter(())
        return self.policy.sitemaps

    @property
    def preferred_host(self) -> str | None:
        if self.policy is None:
            return None
        return self.policy.preferred_host

    def __bool__(self) -> bool:
        return self.decision is Decision.ALLOW

    def __iter__(self) -> Iterator[object]:
        yield self.allowed
        yield self.version
        yield self.stale

    def __len__(self) -> int:
        return 3

    def __getitem__(self, index: int) -> object:
        return (self.allowed, self.version, self.stale)[index]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bool):
            return self.allowed is other
        if isinstance(other, str):
            return str(self.decision) == other
        if isinstance(other, Decision):
            return self.decision is other
        if isinstance(other, (tuple, list)):
            return (self.allowed, self.version, self.stale) == tuple(other)
        if not isinstance(other, RobotsDecision):
            return NotImplemented
        return (
            self.decision,
            self.version,
            self.stale,
            self.state,
            self.origin,
            self.status,
        ) == (
            other.decision,
            other.version,
            other.stale,
            other.state,
            other.origin,
            other.status,
        )

    __hash__ = None  # type: ignore[assignment]


@dataclass(slots=True)
class _CachedPolicy:
    policy: Protego | None = None
    version: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    fetched_at: float | None = None
    last_attempt: float | None = None
    status: int | None = None
    final_url: str | None = None
    consecutive_failures: int = 0
    unavailable: bool = False
    revision: int = 0
    reason: str = ""


@dataclass(slots=True)
class _Loaded:
    entry: _CachedPolicy
    from_cache: bool
    fallback: bool = False


@dataclass(frozen=True, slots=True)
class _URLInfo:
    url: str
    origin: tuple[str, str, int]
    robots_url: str


@dataclass(frozen=True, slots=True)
class _NormalizedResponse:
    status: int | None
    content: str | bytes | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    final_url: str | None = None
    redirect_count: int = 0
    version: str | None = None

    @property
    def redirects(self) -> int:
        return self.redirect_count


FetchCallback = Callable[..., object]
Clock = Callable[[], float | datetime]


def _decode_content(content: str | bytes | None) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return content


def _header_value(headers: Mapping[str, str] | None, name: str) -> str | None:
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is not None:
            return str(value)
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return None


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    try:
        return _DEFAULT_PORTS[scheme]
    except KeyError:
        raise ValueError(f"A port is required for the {scheme!r} scheme") from None


def _parse_url(url: str) -> _URLInfo:
    if not isinstance(url, str):
        raise TypeError(f"Expected a str URL, got {type(url).__name__}")
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"Expected an absolute URL, got {url!r}")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in {url!r}") from exc
    origin = (scheme, host, _effective_port(scheme, port))
    return _URLInfo(url=url, origin=origin, robots_url=_robots_url(origin))


def _robots_url(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, "/robots.txt", "", ""))


def _version_for(headers: Mapping[str, str] | None, content: str) -> str | None:
    etag = _header_value(headers, "ETag")
    if etag:
        return etag
    last_modified = _header_value(headers, "Last-Modified")
    if last_modified:
        return last_modified
    if content:
        return sha256(content.encode("utf-8")).hexdigest()
    return None


def _with_validators(
    headers: Mapping[str, str] | None,
    etag: str | None,
    last_modified: str | None,
) -> Mapping[str, str]:
    merged = dict(headers or {})
    if etag is not None and _header_value(merged, "ETag") is None:
        merged["ETag"] = str(etag)
    if last_modified is not None and _header_value(merged, "Last-Modified") is None:
        merged["Last-Modified"] = str(last_modified)
    return merged


class RobotsManager:
    """Fetch and cache one ``robots.txt`` policy per origin.

    State is isolated by ``(scheme, host, effective port)``.  The optional
    effective port is the scheme default: 80 for HTTP and 443 for HTTPS, so
    ``http://example.com`` and ``http://example.com:80`` share one entry while
    ``https://example.com`` and ``http://example.com`` do not.

    The fetch callback receives either a :class:`RobotsRequest` or a URL,
    depending on its signature.  It may return a :class:`RobotsResponse`, a
    requests-style response, a mapping, or a tuple.  The result may include
    the actual final URL after redirects; that URL is informational only and
    never changes the origin under which the policy is stored.
    """

    def __init__(
        self,
        fetch: FetchCallback | None = None,
        clock: Clock | None = None,
        user_agent: str | None = None,
        *,
        cache_ttl: float | timedelta = DEFAULT_CACHE_TTL,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        fetcher: FetchCallback | None = None,
        http_fetch: FetchCallback | None = None,
        time_func: Clock | None = None,
        now: Clock | None = None,
        timer: Clock | None = None,
        ttl: float | timedelta | None = None,
        default_user_agent: str | None = None,
        fetch_robots: FetchCallback | None = None,
    ) -> None:
        if fetch is None:
            fetch = fetcher
        if fetch is None:
            fetch = http_fetch
        if fetch is None:
            fetch = fetch_robots
        if fetch is not None and not callable(fetch):
            raise TypeError("fetch must be callable")
        if clock is None:
            clock = time_func if time_func is not None else now
        if clock is None:
            clock = timer
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if ttl is not None:
            cache_ttl = ttl
        if isinstance(cache_ttl, timedelta):
            cache_ttl = cache_ttl.total_seconds()
        if cache_ttl < 0:
            raise ValueError("cache_ttl must not be negative")
        if max_redirects < 0:
            raise ValueError("max_redirects must not be negative")

        self._fetch_callback = fetch
        self._clock: Clock = clock if clock is not None else _time.monotonic
        self._cache_ttl = float(cache_ttl)
        self._max_redirects = int(max_redirects)
        self._default_user_agent = (
            user_agent if user_agent is not None else default_user_agent
        )
        self._entries: dict[tuple[str, str, int], _CachedPolicy] = {}

    @property
    def cache_ttl(self) -> float:
        return self._cache_ttl

    @property
    def max_redirects(self) -> int:
        return self._max_redirects

    def decision(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Return the current decision for *url*.

        A fresh cached policy is used without calling the fetch callback.  An
        absent or stale entry is fetched, conditionally revalidated with its
        validators, and then evaluated.
        """
        info = _parse_url(url)
        checked_at = self._now()
        loaded = self._load(info.origin, checked_at, force=False)
        return self._make_result(
            info,
            loaded,
            checked_at,
            self._resolve_user_agent(user_agent),
        )

    def check(self, url: str, user_agent: str | None = None) -> RobotsDecision:
        """Alias for :meth:`decision`."""
        return self.decision(url, user_agent)

    def get_decision(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`decision`."""
        return self.decision(url, user_agent)

    def policy_for(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`decision`."""
        return self.decision(url, user_agent)

    def get_policy(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`decision`."""
        return self.decision(url, user_agent)

    def policy(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`decision`."""
        return self.decision(url, user_agent)

    def can_fetch(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Return a truthy decision when *url* may be fetched.

        The return value is a :class:`RobotsDecision`; it is false for both a
        disallow decision and an unknown decision.  Use ``.allowed`` to tell
        those cases apart (it is ``None`` when unknown).
        """
        return self.decision(url, user_agent)

    def allows(self, url: str, user_agent: str | None = None) -> bool | None:
        """Return ``True``/``False``, or ``None`` when the state is unknown."""
        return self.decision(url, user_agent).allowed

    def update(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Use a fresh cache when possible, fetching only when stale."""
        return self._force(url, force=False, user_agent=user_agent)

    def fetch(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Force a fetch or conditional revalidation for the URL's origin."""
        return self._force(url, force=True, user_agent=user_agent)

    def refresh(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`fetch`."""
        return self._force(url, force=True, user_agent=user_agent)

    def get(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`update`."""
        return self._force(url, force=False, user_agent=user_agent)

    def load(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> RobotsDecision:
        """Alias for :meth:`update`."""
        return self._force(url, force=False, user_agent=user_agent)

    def parser_for(self, url: str) -> Protego | None:
        """Return the current parser for the URL's origin, if one exists."""
        return self.update(url).policy

    def get_parser(self, url: str) -> Protego | None:
        """Alias for :meth:`parser_for`."""
        return self.parser_for(url)

    def clear(self) -> None:
        """Discard every cached origin."""
        self._entries.clear()

    def reset(self) -> None:
        """Alias for :meth:`clear`."""
        self.clear()

    def state(self, url: str, user_agent: str | None = None) -> RobotsState:
        """Return the state backing the current decision for *url*."""
        return self.decision(url, user_agent).state

    def _force(
        self,
        url: str,
        *,
        force: bool,
        user_agent: str | None,
    ) -> RobotsDecision:
        info = _parse_url(url)
        checked_at = self._now()
        loaded = self._load(info.origin, checked_at, force=force)
        return self._make_result(
            info,
            loaded,
            checked_at,
            self._resolve_user_agent(user_agent),
        )

    def _resolve_user_agent(self, user_agent: str | None) -> str:
        if user_agent is not None:
            return user_agent
        if self._default_user_agent is not None:
            return self._default_user_agent
        return "*"

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value)

    def _fresh(self, entry: _CachedPolicy, now: float) -> bool:
        return entry.fetched_at is not None and now - entry.fetched_at < self._cache_ttl

    def _load(
        self,
        origin: tuple[str, str, int],
        now: float,
        *,
        force: bool,
    ) -> _Loaded:
        entry = self._entries.get(origin)
        if entry is not None and not force and self._fresh(entry, now):
            return _Loaded(entry, from_cache=True)

        if entry is None:
            entry = _CachedPolicy()
            self._entries[origin] = entry

        response, failure = self._fetch_chain(origin, entry)
        if failure is not None:
            fallback = self._record_failure(entry, now, failure)
            return _Loaded(entry, from_cache=fallback, fallback=fallback)

        assert response is not None
        from_cache = self._apply_response(entry, now, response)
        return _Loaded(
            entry,
            from_cache=from_cache,
            fallback=from_cache and response.status != 304,
        )

    def _fetch_chain(
        self,
        origin: tuple[str, str, int],
        entry: _CachedPolicy,
    ) -> tuple[_NormalizedResponse | None, str | None]:
        if self._fetch_callback is None:
            return None, "no fetch callback was provided"

        url = _robots_url(origin)
        etag = entry.etag if entry.policy is not None else None
        last_modified = entry.last_modified if entry.policy is not None else None
        request = RobotsRequest(url, etag=etag, last_modified=last_modified)
        seen = {url}
        hops = 0

        while True:
            try:
                raw = self._invoke_fetch(request)
                response = self._normalize_response(raw)
            except Exception as exc:  # noqa: BLE001 - a fetch failure is data.
                logger.debug("robots.txt fetch failed for %s: %s", request.url, exc)
                return None, f"network error: {exc.__class__.__name__}: {exc}"

            reported = response.redirect_count
            if reported > self._max_redirects:
                return None, (
                    f"redirect limit exceeded ({reported} > {self._max_redirects})"
                )

            status = response.status
            if status is None:
                return None, "fetch callback returned no HTTP status"

            if status == 304:
                return self._with_final_url(response, request.url), None

            if 300 <= status < 400:
                location = _header_value(response.headers, "Location")
                if not location:
                    return None, f"redirect status {status} without a Location header"
                hops += 1
                if hops > self._max_redirects:
                    return None, (
                        f"redirect limit exceeded ({hops} > {self._max_redirects})"
                    )
                next_url = urljoin(request.url, location)
                if next_url in seen:
                    return None, "redirect loop detected"
                seen.add(next_url)
                request = RobotsRequest(next_url, redirects=hops)
                continue

            return self._with_final_url(response, request.url), None

    @staticmethod
    def _with_final_url(
        response: _NormalizedResponse,
        url: str,
    ) -> _NormalizedResponse:
        if response.final_url:
            return response
        return replace(response, final_url=url)

    def _invoke_fetch(self, request: RobotsRequest) -> object:
        assert self._fetch_callback is not None
        callback = self._fetch_callback
        try:
            signature = inspect.signature(callback)
        except (TypeError, ValueError):
            return callback(request)

        parameters = signature.parameters
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
        names = set(parameters)
        first = next(iter(parameters.values()), None)

        request_first = first is not None and first.name in {
            "request",
            "req",
            "robots_request",
        }
        if request_first and "url" not in names:
            args: tuple[object, ...] = (request,)
        else:
            args = (request.url,)

        kwargs: dict[str, object] = {}
        if "etag" in names:
            kwargs["etag"] = request.etag
        elif "if_none_match" in names:
            kwargs["if_none_match"] = request.etag
        elif accepts_kwargs and request.etag is not None:
            kwargs["etag"] = request.etag
        if "last_modified" in names:
            kwargs["last_modified"] = request.last_modified
        elif "if_modified_since" in names:
            kwargs["if_modified_since"] = request.last_modified
        elif accepts_kwargs and request.last_modified is not None:
            kwargs["last_modified"] = request.last_modified
        if "headers" in names or (accepts_kwargs and request.headers):
            kwargs["headers"] = request.headers
        if "redirects" in names or (accepts_kwargs and request.redirects):
            kwargs["redirects"] = request.redirects
        if "request" in names and not request_first:
            kwargs["request"] = request

        return callback(*args, **kwargs)

    def _normalize_response(self, raw: object) -> _NormalizedResponse:
        if isinstance(raw, RobotsResponse):
            return _NormalizedResponse(
                status=raw.status,
                content=raw.content,
                headers=raw.headers,
                final_url=raw.final_url,
                redirect_count=raw.redirect_count or len(raw.history),
                version=raw.version,
            )

        if isinstance(raw, Mapping):
            status = raw.get("status", raw.get("status_code"))
            content = raw.get("content", raw.get("text", raw.get("body")))
            headers = _as_headers(raw.get("headers", {}))
            headers = _with_validators(
                headers,
                _as_optional_str(raw.get("etag")),
                _as_optional_str(raw.get("last_modified")),
            )
            final_url = raw.get("final_url", raw.get("redirected_url", raw.get("url")))
            redirect_count = raw.get("redirect_count", raw.get("redirects", 0))
            return _NormalizedResponse(
                status=_as_status(status),
                content=content if isinstance(content, (str, bytes)) else None,
                headers=headers,
                final_url=str(final_url) if final_url else None,
                redirect_count=_as_int(redirect_count, 0),
                version=_as_optional_str(raw.get("version")),
            )

        if isinstance(raw, (tuple, list)):
            values = list(raw)
            if not values:
                return _NormalizedResponse(status=None)
            status = _as_status(values[0])
            content = values[1] if len(values) > 1 else None
            headers = values[2] if len(values) > 2 else {}
            final_url = values[3] if len(values) > 3 else None
            version = values[4] if len(values) > 4 else None
            if isinstance(content, Mapping) and not isinstance(headers, Mapping):
                content, headers = headers, content
            if len(values) == 3 and isinstance(headers, str):
                final_url, headers = headers, {}
            return _NormalizedResponse(
                status=status,
                content=content if isinstance(content, (str, bytes)) else None,
                headers=_as_headers(headers),
                final_url=str(final_url) if final_url else None,
                version=_as_optional_str(version),
            )

        status = _as_status(getattr(raw, "status_code", getattr(raw, "status", None)))
        content = getattr(raw, "text", None)
        if content is None:
            content = getattr(raw, "content", None)
        if content is None:
            content = getattr(raw, "body", None)
        headers = _as_headers(getattr(raw, "headers", None))
        headers = _with_validators(
            headers,
            _as_optional_str(getattr(raw, "etag", None)),
            _as_optional_str(getattr(raw, "last_modified", None)),
        )
        final_url = (
            getattr(raw, "final_url", None)
            or getattr(raw, "redirected_url", None)
            or getattr(raw, "url", None)
        )
        redirect_count = _as_int(
            getattr(raw, "redirect_count", getattr(raw, "redirects", 0)),
            0,
        )
        history = getattr(raw, "history", None)
        if redirect_count == 0 and history is not None:
            try:
                redirect_count = len(history)
            except TypeError:
                redirect_count = 0
        return _NormalizedResponse(
            status=status,
            content=content if isinstance(content, (str, bytes)) else None,
            headers=headers,
            final_url=str(final_url) if final_url else None,
            redirect_count=redirect_count,
            version=_as_optional_str(getattr(raw, "version", None)),
        )

    def _apply_response(
        self,
        entry: _CachedPolicy,
        now: float,
        response: _NormalizedResponse,
    ) -> bool:
        status = response.status
        assert status is not None
        entry.last_attempt = now
        entry.status = status
        if response.final_url:
            entry.final_url = response.final_url

        if status == 304:
            if entry.policy is None and not entry.unavailable:
                entry.consecutive_failures += 1
                entry.reason = "304 response without a cached policy"
                return False
            entry.fetched_at = now
            entry.consecutive_failures = 0
            etag = _header_value(response.headers, "ETag")
            last_modified = _header_value(response.headers, "Last-Modified")
            if etag:
                entry.etag = etag
            if last_modified:
                entry.last_modified = last_modified
            if response.version:
                entry.version = response.version
            elif etag:
                entry.version = etag
            elif last_modified and entry.version is None:
                entry.version = last_modified
            entry.reason = "not modified; reused the cached policy"
            return True

        if 200 <= status < 300:
            content = _decode_content(response.content)
            entry.policy = Protego.parse(content)
            entry.version = response.version or _version_for(response.headers, content)
            entry.etag = _header_value(response.headers, "ETag")
            entry.last_modified = _header_value(response.headers, "Last-Modified")
            entry.fetched_at = now
            entry.consecutive_failures = 0
            entry.unavailable = False
            entry.revision += 1
            entry.reason = "fetched robots.txt"
            return False

        if 400 <= status < 500:
            entry.policy = None
            entry.version = None
            entry.etag = None
            entry.last_modified = None
            entry.unavailable = True
            entry.fetched_at = now
            entry.consecutive_failures = 0
            entry.reason = f"robots.txt unavailable (HTTP {status}); allow all"
            return False

        failure = f"robots.txt unreachable (HTTP {status})"
        self._record_failure(entry, now, failure)
        return entry.policy is not None or entry.unavailable

    def _record_failure(
        self,
        entry: _CachedPolicy,
        now: float,
        reason: str,
    ) -> bool:
        entry.last_attempt = now
        entry.consecutive_failures += 1
        has_cache = entry.policy is not None or entry.unavailable
        if has_cache:
            entry.reason = f"{reason}; using the cached policy"
        else:
            entry.reason = f"{reason}; no cached policy (decision unknown)"
        return has_cache

    def _make_result(
        self,
        info: _URLInfo,
        loaded: _Loaded,
        checked_at: float,
        user_agent: str | None,
    ) -> RobotsDecision:
        entry = loaded.entry
        fresh = self._fresh(entry, checked_at)
        stale = loaded.fallback or (entry.fetched_at is not None and not fresh)

        if entry.policy is not None:
            if user_agent is not None:
                allowed = entry.policy.can_fetch(info.url, user_agent)
                decision = Decision.ALLOW if allowed else Decision.DISALLOW
            else:
                decision = Decision.ALLOW
            state = (
                RobotsState.FRESH
                if fresh and not loaded.fallback
                else RobotsState.STALE
            )
        elif entry.unavailable:
            decision = Decision.ALLOW
            state = RobotsState.UNAVAILABLE
        elif entry.last_attempt is not None:
            decision = Decision.UNKNOWN
            state = RobotsState.UNREACHABLE
        else:
            decision = Decision.UNKNOWN
            state = RobotsState.UNKNOWN

        return RobotsDecision(
            decision=decision,
            version=entry.version,
            stale=stale,
            state=state,
            policy=entry.policy,
            origin=info.origin,
            robots_url=info.robots_url,
            target_url=info.url,
            final_url=entry.final_url,
            status=entry.status,
            etag=entry.etag,
            last_modified=entry.last_modified,
            fetched_at=entry.fetched_at,
            checked_at=checked_at,
            from_cache=loaded.from_cache,
            fallback=loaded.fallback,
            consecutive_failures=entry.consecutive_failures,
            revision=entry.revision,
            reason=entry.reason,
        )


def _as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _as_status(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_headers(value: object) -> Mapping[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in value.items()}
    items = getattr(value, "items", None)
    if callable(items):
        return {str(key): str(item) for key, item in items()}
    if isinstance(value, (list, tuple)):
        try:
            return {str(key): str(item) for key, item in value}
        except (TypeError, ValueError):
            return {}
    return {}


# Readable aliases, useful at call sites that prefer other spellings.
Decision.ALLOWED = Decision.ALLOW  # type: ignore[attr-defined]
Decision.DISALLOWED = Decision.DISALLOW  # type: ignore[attr-defined]
Decision.DENY = Decision.DISALLOW  # type: ignore[attr-defined]
Decision.DENIED = Decision.DISALLOW  # type: ignore[attr-defined]
Decision.UNDETERMINED = Decision.UNKNOWN  # type: ignore[attr-defined]

# Public aliases.  These names make the manager easy to discover while keeping
# one implementation of each state machine.
RobotsTxtManager = RobotsManager
RobotsPolicyManager = RobotsManager
PolicyResult = RobotsDecision
DecisionResult = RobotsDecision
AccessDecision = Decision
PolicyDecision = Decision
FetchResult = RobotsResponse
RobotsFetchResult = RobotsResponse
FetchRequest = RobotsRequest

# Allow the result class name to be used in the same way as the enum, e.g.
# ``RobotsDecision.ALLOW``.
RobotsDecision.ALLOW = Decision.ALLOW  # type: ignore[attr-defined]
RobotsDecision.DISALLOW = Decision.DISALLOW  # type: ignore[attr-defined]
RobotsDecision.UNKNOWN = Decision.UNKNOWN  # type: ignore[attr-defined]

__all__ = [
    "DEFAULT_CACHE_TTL",
    "DEFAULT_MAX_REDIRECTS",
    "AccessDecision",
    "Clock",
    "Decision",
    "DecisionResult",
    "FetchCallback",
    "FetchRequest",
    "FetchResult",
    "PolicyDecision",
    "PolicyResult",
    "RobotsDecision",
    "RobotsFetchResult",
    "RobotsManager",
    "RobotsPolicyManager",
    "RobotsRequest",
    "RobotsResponse",
    "RobotsState",
    "RobotsTxtManager",
]
