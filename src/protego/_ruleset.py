from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, NamedTuple

from ._urlpattern import _PREFIX, _can_fetch, _FlatRule, _matches, _URLPattern
from ._utils import _hexescape, _parse_time_period, _quote_path, _quote_pattern

if TYPE_CHECKING:
    from datetime import time

    from ._protego import Protego


logger = logging.getLogger(__name__)


class RequestRate(NamedTuple):
    requests: int
    seconds: int
    start_time: time | None
    end_time: time | None


class VisitTime(NamedTuple):
    start_time: time
    end_time: time


class RuleMatch(NamedTuple):
    """A rule that matched a URL, with a pointer to its source."""

    field: str  # "allow" or "disallow"
    pattern: str  # the normalized pattern that was matched against
    line: int | None  # 1-based line number in the robots.txt
    raw: str | None  # the robots.txt line the rule comes from
    derived_from: str | None  # how the rule was auto-derived, if it was


class _Rule(NamedTuple):
    field: str
    value: _URLPattern
    line: int | None = None
    raw: str | None = None
    derived_from: str | None = None


def _rule_match(rule: _Rule) -> RuleMatch:
    return RuleMatch(
        field=rule.field,
        pattern=rule.value._pattern,
        line=rule.line,
        raw=rule.raw,
        derived_from=rule.derived_from,
    )


class _RuleSet:
    """Internal class which stores rules for a user agent."""

    def __init__(self, parser_instance: Protego):
        self.user_agent: str | None = None
        # (line number, raw line) of every user-agent declaration naming
        # this rule set; more than one entry means groups were merged.
        self.user_agent_lines: list[tuple[int, str]] = []
        self._rules: list[_Rule] = []
        self._plain_prefixes: tuple[str, ...] | None = None
        self._flat_rules: list[_FlatRule] = []
        self._special_rules: list[_FlatRule] = []
        self._special_sources: list[int] = []
        self._crawl_delay: float | None = None
        self._req_rate: RequestRate | None = None
        self._visit_time: VisitTime | None = None
        self._parser_instance: Protego = parser_instance

    def applies_to(self, robotname: str) -> int:
        """Return matching score."""
        assert self.user_agent is not None
        robotname = robotname.strip().lower()
        if self.user_agent == "*":
            return 1
        # Match the product token only at a token boundary. This avoids
        # false positives such as "bot" matching "mybot", while still
        # matching a token within a full User-Agent header, e.g.
        # "Mozilla/5.0 (compatible; Foobot/1.0)" matching "foobot".
        index = robotname.find(self.user_agent)
        while index != -1:
            if index == 0 or not (
                robotname[index - 1].isalnum() or robotname[index - 1] in "-_"
            ):
                return len(self.user_agent)
            index = robotname.find(self.user_agent, index + 1)
        return 0

    def _url_pattern(self, pattern: str) -> _URLPattern:
        """Return the URL pattern for a directive value.

        The same value usually appears once per user agent in a robots.txt,
        so patterns are shared across the rule sets of a parser.
        """
        cache = self._parser_instance._url_patterns
        if pattern not in cache:
            cache[pattern] = _URLPattern(_quote_pattern(pattern))
        return cache[pattern]

    def allow(
        self,
        pattern: str,
        line: int | None = None,
        raw: str | None = None,
        derived_from: str | None = None,
    ) -> None:
        if "$" in pattern:
            self.allow(
                pattern.replace("$", _hexescape("$")),
                line=line,
                raw=raw,
                derived_from=f'"$" of {pattern!r} escaped as {_hexescape("$")!r}',
            )

        url_pattern = self._url_pattern(pattern)
        self._rules.append(
            _Rule(
                field="allow",
                value=url_pattern,
                line=line,
                raw=raw,
                derived_from=derived_from,
            )
        )

        # If index.html is allowed, we interpret this as / being allowed too.
        page = "index.html"
        quoted = url_pattern._pattern
        if quoted.endswith(f"/{page}"):
            # Add the rule directly; going through allow() would treat the
            # "$" anchor as a literal dollar sign too.
            self._rules.append(
                _Rule(
                    field="allow",
                    value=_URLPattern(quoted.removesuffix(page) + "$"),
                    line=line,
                    raw=raw,
                    derived_from=f"allowing {quoted!r} also allows its parent",
                )
            )

    def disallow(
        self,
        pattern: str,
        line: int | None = None,
        raw: str | None = None,
        derived_from: str | None = None,
    ) -> None:
        if "$" in pattern:
            self.disallow(
                pattern.replace("$", _hexescape("$")),
                line=line,
                raw=raw,
                derived_from=f'"$" of {pattern!r} escaped as {_hexescape("$")!r}',
            )

        url_pattern = self._url_pattern(pattern)
        self._rules.append(
            _Rule(
                field="disallow",
                value=url_pattern,
                line=line,
                raw=raw,
                derived_from=derived_from,
            )
        )

    def finalize_rules(self) -> None:
        self._rules.sort(
            key=lambda r: (r.value.priority, r.field == "allow"), reverse=True
        )

    def _build_index(self) -> tuple[str, ...]:
        """Flatten the rules for the match loop, and split out the patterns
        that can only match as a prefix of a URL and the rules that can match
        otherwise.

        Built on the first match rather than at parse time because a
        robots.txt declares many rule sets and a crawler queries one.
        """
        prefixes = []
        flat_rules = []
        special = []
        special_sources = []
        for rule_index, rule in enumerate(self._rules):
            pattern = rule.value
            flat_rule = (pattern.kind, pattern.data, rule.field == "disallow")
            flat_rules.append(flat_rule)
            if pattern.kind == _PREFIX:
                prefixes.append(pattern._pattern)
            else:
                special.append(flat_rule)
                special_sources.append(rule_index)
        self._flat_rules = flat_rules
        self._special_rules = special
        self._special_sources = special_sources
        self._plain_prefixes = tuple(prefixes)
        return self._plain_prefixes

    def _indexed_rules(self, url: str) -> tuple[list[_FlatRule], list[int] | None]:
        """Return the flattened rules to match *url* against, in priority
        order, and, when a subset is returned, their indices in
        ``self._rules``.
        """
        prefixes = self._plain_prefixes
        if prefixes is None:
            prefixes = self._build_index()
        # A plain pattern matches only as a prefix of the URL, so a single
        # startswith over all of them rules every one of them out at once.
        if url.startswith(prefixes):
            # Flat rules are built in the order of self._rules.
            return self._flat_rules, None
        return self._special_rules, self._special_sources

    def can_fetch(self, url: str) -> bool:
        """Return if the url can be fetched."""
        url = _quote_path(url)
        rules, _ = self._indexed_rules(url)
        return _can_fetch(rules, url)

    def explain(
        self, url: str, max_other_matches: int | None = 10
    ) -> tuple[bool, RuleMatch | None, tuple[RuleMatch, ...], bool, bool, str]:
        """Match *url* like :meth:`can_fetch` does, and report the outcome.

        Return a tuple ``(allowed, winning_rule, other_matches, truncated,
        allow_tie, quoted_url)`` where *winning_rule* is the rule that
        decided the outcome (``None`` when no rule matched), *other_matches*
        are up to *max_other_matches* further rules that also match,
        *truncated* tells whether more rules matched than reported, and
        *allow_tie* tells whether the winning allow rule shares its priority
        with a matching disallow rule.
        """
        quoted_url = _quote_path(url)
        rules, sources = self._indexed_rules(quoted_url)
        matched = []
        for index, (kind, data, _) in enumerate(rules):
            if _matches(kind, data, quoted_url):
                matched.append(index if sources is None else sources[index])
        if not matched:
            return True, None, (), False, False, quoted_url
        winner = self._rules[matched[0]]
        others = [self._rules[index] for index in matched[1:]]
        allow_tie = winner.field == "allow" and any(
            other.field == "disallow" and other.value.priority == winner.value.priority
            for other in others
        )
        truncated = max_other_matches is not None and len(others) > max_other_matches
        if max_other_matches is not None:
            others = others[:max_other_matches]
        return (
            winner.field == "allow",
            _rule_match(winner),
            tuple(_rule_match(other) for other in others),
            truncated,
            allow_tie,
            quoted_url,
        )

    @property
    def crawl_delay(self) -> float | None:
        """Get & set crawl delay for the rule set."""
        return self._crawl_delay

    @crawl_delay.setter
    def crawl_delay(self, delay: str) -> None:
        try:
            parsed_delay = float(delay)
        except ValueError:
            parsed_delay = None
        if parsed_delay is None or not math.isfinite(parsed_delay) or parsed_delay < 0:
            # Value is malformed, do nothing.
            logger.debug(
                f"Malformed rule at line {self._parser_instance._total_line_seen} : "
                f"cannot set crawl delay to '{delay}'. Ignoring this rule."
            )
            return
        self._crawl_delay = parsed_delay

    @property
    def request_rate(self) -> RequestRate | None:
        """Get & set request rate for the rule set."""
        return self._req_rate

    @request_rate.setter
    def request_rate(self, value: str) -> None:
        try:
            parts = value.split()
            if len(parts) == 2:
                rate, time_period = parts
            else:
                rate, time_period = parts[0], ""

            requests_str, seconds_str = rate.split("/")
            time_unit = seconds_str[-1].lower()
            if time_unit in ("s", "m", "h", "d"):
                seconds = int(seconds_str[:-1])
            else:
                time_unit = "s"
                seconds = int(seconds_str)
            requests = int(requests_str)

            if requests <= 0 or seconds <= 0:
                raise ValueError(f"Request rate must be positive: {value!r}")

            if time_unit == "m":
                seconds *= 60
            elif time_unit == "h":
                seconds *= 3600
            elif time_unit == "d":
                seconds *= 86400

            start_time = None
            end_time = None
            if time_period:
                start_time, end_time = _parse_time_period(time_period)
        except Exception:  # noqa: BLE001
            # Value is malformed, do nothing.
            logger.debug(
                f"Malformed rule at line {self._parser_instance._total_line_seen} : "
                f"cannot set request rate using '{value}'. Ignoring this rule."
            )
            return

        self._req_rate = RequestRate(requests, seconds, start_time, end_time)

    @property
    def visit_time(self) -> VisitTime | None:
        """Get & set visit time for the rule set."""
        return self._visit_time

    @visit_time.setter
    def visit_time(self, value: str) -> None:
        try:
            try:
                # "0400-0845"
                start_time, end_time = _parse_time_period(value)
            except ValueError:
                # "0400 0845"
                start_time, end_time = _parse_time_period(value, separator=" ")
        except Exception:  # noqa: BLE001
            logger.debug(
                f"Malformed rule at line {self._parser_instance._total_line_seen} : "
                f"cannot set visit time using '{value}'. Ignoring this rule."
            )
            return
        self._visit_time = VisitTime(start_time, end_time)
