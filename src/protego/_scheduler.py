"""Optional reservation scheduler for politeness-aware crawling.

This module is independent from the parser: it never sleeps and never
performs network requests. It only computes, for a given origin and the
policy of a selected user agent, the earliest moment at which a request
would satisfy the ``Crawl-delay``, ``Request-rate`` and ``Visit-time``
directives simultaneously, taking already reserved and already executed
requests into account.

All moments are explicit UTC: naive datetimes are interpreted as UTC and
aware datetimes are converted to UTC. Time-of-day windows (``Visit-time``
and the optional ``Request-rate`` period) are read as UTC and may cross
midnight; the start is inclusive and the end is exclusive.
"""

from __future__ import annotations

import itertools
import threading
from bisect import bisect_right, insort
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, NamedTuple

from ._ruleset import RequestRate, VisitTime

if TYPE_CHECKING:
    from ._protego import Protego

_UTC = timezone.utc
_DEFAULT_HORIZON = timedelta(days=7)


def _as_utc(moment: datetime) -> datetime:
    """Return the moment as an aware UTC datetime."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=_UTC)
    return moment.astimezone(_UTC)


def _in_period(instant: time, start: time, end: time) -> bool:
    """Return whether a time of day falls in a [start, end) UTC period.

    The period may cross midnight. A period with equal start and end is
    read as covering the whole day.
    """
    if start == end:
        return True
    if start < end:
        return start <= instant < end
    return instant >= start or instant < end


class ReservationState(Enum):
    """Lifecycle of a reservation."""

    PENDING = "pending"
    STARTED = "started"
    CANCELLED = "cancelled"


class Slot(NamedTuple):
    """Result of a slot lookup.

    When ``available`` is False, ``at`` is None and ``reason`` explains
    why no executable moment was found within the search horizon.
    """

    available: bool
    at: datetime | None
    reason: str | None = None


@dataclass(frozen=True)
class Policy:
    """Politeness policy of one user agent on one origin.

    ``version`` identifies the policy revision; handing the scheduler a
    policy that differs from the stored one (including by version only)
    triggers a revalidation of the unexecuted reservations of the origin.
    """

    crawl_delay: float | None = None
    request_rate: RequestRate | None = None
    visit_time: VisitTime | None = None
    version: int = 0

    @classmethod
    def from_protego(
        cls, parser: Protego, user_agent: str, version: int = 0
    ) -> Policy:
        """Build a policy from the directives a parser reports for an agent."""
        return cls(
            crawl_delay=parser.crawl_delay(user_agent),
            request_rate=parser.request_rate(user_agent),
            visit_time=parser.visit_time(user_agent),
            version=version,
        )


def _within_windows(policy: Policy, moment: datetime) -> bool:
    """Return whether the moment is inside every configured UTC window."""
    instant = moment.time()
    visit_time = policy.visit_time
    if visit_time is not None and not _in_period(
        instant, visit_time.start_time, visit_time.end_time
    ):
        return False
    rate = policy.request_rate
    return not (
        rate is not None
        and rate.start_time is not None
        and rate.end_time is not None
        and not _in_period(instant, rate.start_time, rate.end_time)
    )


def satisfies(
    policy: Policy, events: list[datetime] | tuple[datetime, ...], moment: datetime
) -> bool:
    """Return whether a request at ``moment`` satisfies the policy.

    ``events`` holds the UTC moments of the other requests of the same
    origin (reserved or already executed). The check is pure: every moment
    can be recomputed independently from the policy and the event list.
    """
    moment = _as_utc(moment)
    if not _within_windows(policy, moment):
        return False
    merged = sorted(_as_utc(event) for event in events)
    insort(merged, moment)
    if policy.crawl_delay:
        delay = timedelta(seconds=policy.crawl_delay)
        for earlier, later in zip(merged, merged[1:]):
            if later - earlier < delay:
                return False
    rate = policy.request_rate
    if rate is not None:
        window = timedelta(seconds=rate.seconds)
        for index, event in enumerate(merged):
            # Sliding window: at most ``requests`` events in (event-w, event].
            first = bisect_right(merged, event - window)
            if index + 1 - first > rate.requests:
                return False
    return True


def _window_starts(
    policy: Policy, first_day: datetime, last_day: datetime
) -> list[datetime]:
    starts = []
    periods = []
    if policy.visit_time is not None:
        periods.append(policy.visit_time.start_time)
    rate = policy.request_rate
    if rate is not None and rate.start_time is not None:
        periods.append(rate.start_time)
    day = first_day.date()
    while day <= last_day.date():
        for start in periods:
            starts.append(datetime.combine(day, start, tzinfo=_UTC))
        day += timedelta(days=1)
    return starts


def earliest_slot(
    policy: Policy,
    events: list[datetime] | tuple[datetime, ...],
    now: datetime,
    horizon: timedelta = _DEFAULT_HORIZON,
) -> Slot:
    """Return the earliest moment at or after ``now`` satisfying the policy.

    The search is bounded by ``horizon``; when no moment qualifies, an
    unavailable slot is returned instead of searching the future forever.
    """
    now = _as_utc(now)
    events = sorted(_as_utc(event) for event in events)
    limit = now + horizon
    candidates = {now}
    if policy.crawl_delay:
        delay = timedelta(seconds=policy.crawl_delay)
        candidates.update(event + delay for event in events)
    rate = policy.request_rate
    if rate is not None:
        window = timedelta(seconds=rate.seconds)
        candidates.update(event + window for event in events)
    candidates.update(_window_starts(policy, now, limit))
    for moment in sorted(candidates):
        if moment < now or moment > limit:
            continue
        if satisfies(policy, events, moment):
            return Slot(available=True, at=moment)
    return Slot(
        available=False,
        at=None,
        reason=f"no executable moment within {horizon} after {now.isoformat()}",
    )


@dataclass
class Reservation:
    """A reserved moment for one request on an origin."""

    id: int
    origin: str
    user_agent: str
    state: ReservationState
    scheduled_at: datetime | None
    policy_version: int
    started_at: datetime | None = None


class _OriginState:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.executed: list[datetime] = []
        self.pending: dict[int, Reservation] = {}


class ReservationScheduler:
    """Track reservations per origin and compute executable moments.

    The scheduler is passive: it never sleeps and never fetches. A
    ``clock`` callable returning the current time (UTC) can be injected,
    which makes every computation reproducible in tests.
    """

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
        horizon: timedelta = _DEFAULT_HORIZON,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(_UTC))
        self._horizon = horizon
        self._lock = threading.Lock()
        self._origins: dict[str, _OriginState] = {}
        self._reservations: dict[int, Reservation] = {}
        self._ids = itertools.count(1)

    def _now(self) -> datetime:
        return _as_utc(self._clock())

    def _origin(self, origin: str) -> _OriginState:
        if origin not in self._origins:
            self._origins[origin] = _OriginState(Policy())
        return self._origins[origin]

    def _timeline(self, state: _OriginState) -> list[datetime]:
        moments = list(state.executed)
        moments.extend(
            reservation.scheduled_at
            for reservation in state.pending.values()
            if reservation.scheduled_at is not None
        )
        return sorted(moments)

    def policy(self, origin: str) -> Policy:
        """Return the policy currently stored for the origin."""
        with self._lock:
            return self._origin(origin).policy

    def set_policy(self, origin: str, policy: Policy) -> bool:
        """Store a policy; revalidate pending reservations if it changed."""
        with self._lock:
            state = self._origin(origin)
            if state.policy == policy:
                return False
            state.policy = policy
            self._revalidate(origin)
            return True

    def _revalidate(self, origin: str) -> None:
        """Recheck unexecuted reservations against the current policy."""
        state = self._origin(origin)
        now = self._now()
        ordered = sorted(
            state.pending.values(),
            key=lambda r: (r.scheduled_at is None, r.scheduled_at, r.id),
        )
        scheduled: list[datetime] = []
        for reservation in ordered:
            slot = earliest_slot(
                state.policy, state.executed + scheduled, now, self._horizon
            )
            reservation.scheduled_at = slot.at if slot.available else None
            reservation.policy_version = state.policy.version
            if slot.available:
                scheduled.append(slot.at)

    def next_slot(self, origin: str, after: datetime | None = None) -> Slot:
        """Return the earliest executable moment for the origin."""
        with self._lock:
            state = self._origin(origin)
            moment = _as_utc(after) if after is not None else self._now()
            return earliest_slot(
                state.policy, self._timeline(state), moment, self._horizon
            )

    def reserve(
        self,
        origin: str,
        user_agent: str = "*",
        policy: Policy | None = None,
        after: datetime | None = None,
    ) -> Reservation | None:
        """Reserve the earliest executable moment, or None if there is none.

        Concurrent reservations on the same origin are serialized through
        the internal lock and always account for one another, so two
        reservations never receive conflicting moments.
        """
        with self._lock:
            state = self._origin(origin)
            if policy is not None and policy != state.policy:
                state.policy = policy
                self._revalidate(origin)
            moment = _as_utc(after) if after is not None else self._now()
            slot = earliest_slot(
                state.policy, self._timeline(state), moment, self._horizon
            )
            if not slot.available:
                return None
            reservation = Reservation(
                id=next(self._ids),
                origin=origin,
                user_agent=user_agent,
                state=ReservationState.PENDING,
                scheduled_at=slot.at,
                policy_version=state.policy.version,
            )
            state.pending[reservation.id] = reservation
            self._reservations[reservation.id] = reservation
            return reservation

    def start(self, reservation_id: int) -> Reservation:
        """Mark a pending reservation as started at the current moment."""
        with self._lock:
            reservation = self._reservations[reservation_id]
            if reservation.state is not ReservationState.PENDING:
                msg = f"reservation {reservation_id} is {reservation.state.value}"
                raise ValueError(msg)
            reservation.state = ReservationState.STARTED
            reservation.started_at = self._now()
            state = self._origin(reservation.origin)
            del state.pending[reservation.id]
            state.executed.append(reservation.started_at)
            state.executed.sort()
            return reservation

    def cancel(self, reservation_id: int) -> Reservation:
        """Cancel a reservation.

        Cancelling a pending reservation frees its moment. Cancelling a
        started reservation does not reclaim the quota of the request that
        already happened: its moment stays on the origin timeline.
        """
        with self._lock:
            reservation = self._reservations[reservation_id]
            if reservation.state is ReservationState.CANCELLED:
                return reservation
            if reservation.state is ReservationState.PENDING:
                state = self._origin(reservation.origin)
                del state.pending[reservation.id]
            reservation.state = ReservationState.CANCELLED
            return reservation

    def get(self, reservation_id: int) -> Reservation:
        """Return a reservation by id."""
        return self._reservations[reservation_id]

    def reservations(
        self, origin: str | None = None, state: ReservationState | None = None
    ) -> list[Reservation]:
        """List reservations, optionally filtered by origin and state."""
        with self._lock:
            result = []
            for reservation in self._reservations.values():
                if origin is not None and reservation.origin != origin:
                    continue
                if state is not None and reservation.state is not state:
                    continue
                result.append(reservation)
            return result

    def satisfies(self, origin: str, moment: datetime) -> bool:
        """Independently recompute whether a moment satisfies the policy."""
        with self._lock:
            state = self._origin(origin)
            return satisfies(state.policy, self._timeline(state), moment)
