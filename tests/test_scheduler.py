from datetime import datetime, timedelta, timezone

import pytest

from protego import (
    Policy,
    Protego,
    RequestRate,
    ReservationScheduler,
    ReservationState,
    VisitTime,
)
from protego._scheduler import earliest_slot, satisfies

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


class FixedClock:
    def __init__(self, start=T0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def make_scheduler(policy=None, clock=None, origin="example.com", **kwargs):
    scheduler = ReservationScheduler(clock=clock or FixedClock(), **kwargs)
    if policy is not None:
        scheduler.set_policy(origin, policy)
    return scheduler


class TestCrawlDelay:
    def test_successive_reservations_are_spaced(self):
        scheduler = make_scheduler(Policy(crawl_delay=10.0))
        moments = [
            scheduler.reserve("example.com").scheduled_at for _ in range(3)
        ]
        assert moments == [T0, T0 + timedelta(seconds=10), T0 + timedelta(seconds=20)]

    def test_boundary_moment_is_executable(self):
        policy = Policy(crawl_delay=10.0)
        events = [T0]
        assert satisfies(policy, events, T0 + timedelta(seconds=10))
        assert not satisfies(policy, events, T0 + timedelta(seconds=9))

    def test_fractional_delay(self):
        scheduler = make_scheduler(Policy(crawl_delay=0.5))
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        assert second.scheduled_at == first.scheduled_at + timedelta(seconds=0.5)


class TestRequestRate:
    def test_sliding_window_boundary(self):
        policy = Policy(request_rate=RequestRate(2, 10, None, None))
        scheduler = make_scheduler(policy)
        moments = [
            scheduler.reserve("example.com").scheduled_at for _ in range(4)
        ]
        # The first two requests burst at T0, the window then slides.
        assert moments[:2] == [T0, T0]
        assert moments[2] == T0 + timedelta(seconds=10)
        assert moments[3] == T0 + timedelta(seconds=10)

    def test_window_edge_excludes_oldest_event(self):
        policy = Policy(request_rate=RequestRate(1, 10, None, None))
        events = [T0]
        assert satisfies(policy, events, T0 + timedelta(seconds=10))
        assert not satisfies(policy, events, T0 + timedelta(seconds=10, microseconds=-1))

    def test_rate_with_time_window(self):
        policy = Policy(
            request_rate=RequestRate(
                1, 10, datetime.strptime("0900", "%H%M").time(),
                datetime.strptime("1700", "%H%M").time(),
            )
        )
        clock = FixedClock(datetime(2026, 1, 1, 8, 0, tzinfo=UTC))
        scheduler = make_scheduler(policy, clock)
        reservation = scheduler.reserve("example.com")
        assert reservation.scheduled_at == datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


class TestVisitTime:
    def test_cross_midnight_window(self):
        policy = Policy(
            visit_time=VisitTime(
                datetime.strptime("2300", "%H%M").time(),
                datetime.strptime("0200", "%H%M").time(),
            )
        )
        # Before the window: wait for 23:00.
        clock = FixedClock(datetime(2026, 1, 1, 22, 0, tzinfo=UTC))
        scheduler = make_scheduler(policy, clock)
        assert scheduler.reserve("example.com").scheduled_at == datetime(
            2026, 1, 1, 23, 0, tzinfo=UTC
        )
        # Inside the window, after midnight: immediate.
        clock.now = datetime(2026, 1, 2, 1, 0, tzinfo=UTC)
        assert make_scheduler(policy, clock).next_slot("example.com").at == clock.now
        # At the exclusive end: wait for the next 23:00.
        clock.now = datetime(2026, 1, 2, 2, 0, tzinfo=UTC)
        assert make_scheduler(policy, clock).next_slot("example.com").at == datetime(
            2026, 1, 2, 23, 0, tzinfo=UTC
        )

    def test_window_boundaries(self):
        policy = Policy(
            visit_time=VisitTime(
                datetime.strptime("0400", "%H%M").time(),
                datetime.strptime("0845", "%H%M").time(),
            )
        )
        clock = FixedClock(datetime(2026, 1, 1, 4, 0, tzinfo=UTC))
        scheduler = make_scheduler(policy, clock)
        # Start is inclusive.
        assert scheduler.next_slot("example.com").at == clock.now
        # End is exclusive.
        clock.now = datetime(2026, 1, 1, 8, 45, tzinfo=UTC)
        assert scheduler.next_slot("example.com").at == datetime(
            2026, 1, 2, 4, 0, tzinfo=UTC
        )

    def test_naive_datetime_is_read_as_utc(self):
        policy = Policy(
            visit_time=VisitTime(
                datetime.strptime("0400", "%H%M").time(),
                datetime.strptime("0845", "%H%M").time(),
            )
        )
        slot = earliest_slot(policy, [], datetime(2026, 1, 1, 3, 0))
        assert slot.at == datetime(2026, 1, 1, 4, 0, tzinfo=UTC)


class TestCombinedConstraints:
    def test_all_constraints_simultaneously(self):
        policy = Policy(
            crawl_delay=5.0,
            request_rate=RequestRate(3, 60, None, None),
            visit_time=VisitTime(
                datetime.strptime("2300", "%H%M").time(),
                datetime.strptime("0200", "%H%M").time(),
            ),
        )
        clock = FixedClock(datetime(2026, 1, 1, 22, 30, tzinfo=UTC))
        scheduler = make_scheduler(policy, clock)
        reservations = [scheduler.reserve("example.com") for _ in range(40)]
        moments = [r.scheduled_at for r in reservations]
        # Everything fits inside the nightly window, spaced by the delay.
        assert moments[0] == datetime(2026, 1, 1, 23, 0, tzinfo=UTC)
        # Every moment is independently recomputed against the others.
        for index, moment in enumerate(moments):
            others = moments[:index] + moments[index + 1 :]
            assert satisfies(policy, others, moment)
        # The rate limiter kicked in: no 4 moments within any 60 seconds.
        for later in moments:
            count = sum(
                1 for earlier in moments
                if later - timedelta(seconds=60) < earlier <= later
            )
            assert count <= 3

    def test_concurrent_reservations_never_conflict(self):
        policy = Policy(crawl_delay=2.0, request_rate=RequestRate(5, 30, None, None))
        scheduler = make_scheduler(policy)
        reservations = [scheduler.reserve("example.com") for _ in range(50)]
        moments = sorted(r.scheduled_at for r in reservations)
        assert all(
            r.state is ReservationState.PENDING for r in reservations
        )
        for earlier, later in zip(moments, moments[1:]):
            assert later - earlier >= timedelta(seconds=2)
        for moment in moments:
            others = [m for m in moments if m != moment]
            assert satisfies(policy, others, moment)


class TestLifecycle:
    def test_cancel_pending_frees_the_slot(self):
        scheduler = make_scheduler(Policy(crawl_delay=10.0))
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        scheduler.cancel(first.id)
        assert scheduler.get(first.id).state is ReservationState.CANCELLED
        third = scheduler.reserve("example.com")
        assert third.scheduled_at == first.scheduled_at
        assert second.scheduled_at == T0 + timedelta(seconds=10)

    def test_cancel_started_does_not_reclaim_quota(self):
        policy = Policy(request_rate=RequestRate(1, 10, None, None))
        clock = FixedClock()
        scheduler = make_scheduler(policy, clock)
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        assert second.scheduled_at == T0 + timedelta(seconds=10)
        scheduler.start(first.id)
        scheduler.cancel(first.id)
        # The executed request still consumes its window.
        third = scheduler.reserve("example.com")
        assert third.scheduled_at == T0 + timedelta(seconds=20)

    def test_start_records_the_actual_moment(self):
        clock = FixedClock()
        scheduler = make_scheduler(Policy(crawl_delay=10.0), clock)
        reservation = scheduler.reserve("example.com")
        clock.advance(seconds=10)
        scheduler.start(reservation.id)
        assert reservation.state is ReservationState.STARTED
        assert reservation.started_at == T0 + timedelta(seconds=10)
        with pytest.raises(ValueError):
            scheduler.start(reservation.id)

    def test_states_are_distinguished(self):
        scheduler = make_scheduler(Policy(crawl_delay=10.0))
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        third = scheduler.reserve("example.com")
        scheduler.start(first.id)
        scheduler.cancel(second.id)
        pending = scheduler.reservations("example.com", ReservationState.PENDING)
        started = scheduler.reservations("example.com", ReservationState.STARTED)
        cancelled = scheduler.reservations("example.com", ReservationState.CANCELLED)
        assert [r.id for r in pending] == [third.id]
        assert [r.id for r in started] == [first.id]
        assert [r.id for r in cancelled] == [second.id]


class TestPolicyChange:
    def test_pending_reservations_are_revalidated(self):
        clock = FixedClock()
        scheduler = make_scheduler(Policy(crawl_delay=10.0, version=1), clock)
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        assert second.scheduled_at == T0 + timedelta(seconds=10)
        changed = scheduler.set_policy(
            "example.com", Policy(crawl_delay=60.0, version=2)
        )
        assert changed
        assert first.scheduled_at == T0
        assert second.scheduled_at == T0 + timedelta(seconds=60)
        assert second.policy_version == 2

    def test_version_bump_alone_triggers_revalidation(self):
        scheduler = make_scheduler(Policy(crawl_delay=10.0, version=1))
        scheduler.reserve("example.com")
        assert scheduler.set_policy(
            "example.com", Policy(crawl_delay=10.0, version=2)
        )
        assert not scheduler.set_policy(
            "example.com", Policy(crawl_delay=10.0, version=2)
        )

    def test_unschedulable_reservation_stays_pending_without_moment(self):
        scheduler = make_scheduler(
            Policy(crawl_delay=10.0, version=1),
            horizon=timedelta(hours=1),
        )
        first = scheduler.reserve("example.com")
        second = scheduler.reserve("example.com")
        assert second.scheduled_at == T0 + timedelta(seconds=10)
        scheduler.set_policy("example.com", Policy(crawl_delay=7200.0, version=2))
        assert first.scheduled_at == T0
        # The delay no longer fits the horizon: pending, but unscheduled.
        assert second.scheduled_at is None
        assert second.state is ReservationState.PENDING

    def test_pending_reservation_follows_policy_window(self):
        scheduler = make_scheduler(
            Policy(crawl_delay=10.0, version=1),
            horizon=timedelta(days=1),
        )
        reservation = scheduler.reserve("example.com")
        scheduler.set_policy(
            "example.com",
            Policy(
                crawl_delay=10.0,
                visit_time=VisitTime(
                    datetime.strptime("1200", "%H%M").time(),
                    datetime.strptime("1201", "%H%M").time(),
                ),
                version=2,
            ),
        )
        assert reservation.scheduled_at == T0 + timedelta(hours=12)
        scheduler.set_policy(
            "example.com",
            Policy(
                visit_time=VisitTime(
                    datetime.strptime("0000", "%H%M").time(),
                    datetime.strptime("0000", "%H%M").time(),
                ),
                version=3,
            ),
        )
        # Equal start and end means the whole day: rescheduled to now.
        assert reservation.scheduled_at == T0


class TestNoSlotAvailable:
    def test_explicit_unavailable_result(self):
        policy = Policy(
            crawl_delay=7200.0,
            visit_time=VisitTime(
                datetime.strptime("0000", "%H%M").time(),
                datetime.strptime("0100", "%H%M").time(),
            ),
        )
        scheduler = make_scheduler(policy, horizon=timedelta(days=3))
        # One slot per night, four nights within the horizon.
        for day in range(4):
            reservation = scheduler.reserve("example.com")
            assert reservation.scheduled_at == T0 + timedelta(days=day)
        assert scheduler.reserve("example.com") is None
        slot = scheduler.next_slot("example.com")
        assert not slot.available
        assert slot.at is None
        assert slot.reason

    def test_search_is_bounded(self):
        policy = Policy(
            visit_time=VisitTime(
                datetime.strptime("0000", "%H%M").time(),
                datetime.strptime("0001", "%H%M").time(),
            )
        )
        slot = earliest_slot(
            policy, [], T0 + timedelta(hours=2), horizon=timedelta(minutes=30)
        )
        assert not slot.available


class TestProtegoIntegration:
    def test_policy_from_parsed_robots_txt(self):
        robotstxt = """
        User-agent: mybot
        Crawl-delay: 4
        Request-rate: 2/10s 0900-1700
        Visit-time: 0800-1800
        """
        parser = Protego.parse(robotstxt)
        policy = Policy.from_protego(parser, "mybot", version=1)
        assert policy.crawl_delay == 4.0
        assert policy.request_rate.requests == 2
        clock = FixedClock(datetime(2026, 1, 1, 8, 30, tzinfo=UTC))
        scheduler = make_scheduler(policy, clock)
        first = scheduler.reserve("example.com", user_agent="mybot")
        second = scheduler.reserve("example.com", user_agent="mybot")
        third = scheduler.reserve("example.com", user_agent="mybot")
        # Visit-time opens at 08:00, the rate window at 09:00.
        assert first.scheduled_at == datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
        assert second.scheduled_at == datetime(2026, 1, 1, 9, 0, 4, tzinfo=UTC)
        # Two requests per 10 seconds: the third waits for the window to slide.
        assert third.scheduled_at == datetime(2026, 1, 1, 9, 0, 10, tzinfo=UTC)

    def test_origins_are_independent(self):
        scheduler = make_scheduler(Policy(crawl_delay=10.0))
        first = scheduler.reserve("a.com")
        second = scheduler.reserve("b.com")
        assert first.scheduled_at == second.scheduled_at == T0
