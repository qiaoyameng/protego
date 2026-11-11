from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Self
from urllib.parse import urlparse

from ._explain import (
    DEFAULT_OTHER_RULES_BUDGET,
    FetchExplanation,
    RuleSource,
    UserAgentExplanation,
)
from ._ruleset import RequestRate, VisitTime, _RuleSet
from ._utils import _quote_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ._urlpattern import _URLPattern


logger = logging.getLogger(__name__)


_DISALLOW_DIRECTIVE = {
    "disallow",
    "dissallow",
    "dissalow",
    "disalow",
    "diasllow",
    "disallaw",
}
_ALLOW_DIRECTIVE = {"allow"}
_USER_AGENT_DIRECTIVE = {"user-agent", "useragent", "user agent"}
_SITEMAP_DIRECTIVE = {"sitemap", "sitemaps", "site-map"}
_CRAWL_DELAY_DIRECTIVE = {"crawl-delay", "crawl delay"}
_REQUEST_RATE_DIRECTIVE = {"request-rate", "request rate"}
_VISIT_TIME_DIRECTIVE = {"visit-time", "visit time"}
_HOST_DIRECTIVE = {"host"}

# Directives that apply to the whole site rather than to a record group.
_SITE_WIDE_DIRECTIVES = _SITEMAP_DIRECTIVE | _HOST_DIRECTIVE

_ALL_DIRECTIVES = (
    _DISALLOW_DIRECTIVE
    | _ALLOW_DIRECTIVE
    | _USER_AGENT_DIRECTIVE
    | _SITEMAP_DIRECTIVE
    | _CRAWL_DELAY_DIRECTIVE
    | _REQUEST_RATE_DIRECTIVE
    | _VISIT_TIME_DIRECTIVE
    | _HOST_DIRECTIVE
)

_MAX_DIRECTIVE_WORDS = max(len(alias.split()) for alias in _ALL_DIRECTIVES)


def _is_valid_directive_field(field: str) -> bool:
    return field in _ALL_DIRECTIVES


def _extract_directive(line: str) -> tuple[str, str] | None:
    """Split a non-empty line into a lowercased directive field and a
    stripped value, or return None if the line cannot be read as a
    directive. A line with "<field>:<value>" shape is returned even when
    the field is not a known directive, so that the caller can count it as
    an invalid directive.

    We are more generous than the specs: we allow e.g. "User-agent: foo",
    "User-agent foo", "User agent: foo" and "User agent foo" even though all
    specs only specify the first form. We also tolerate some misspellings.
    """
    field: str | None = None
    value = ""
    if ":" in line:
        field, raw_value = line.split(":", 1)
        field = field.strip().lower()
        value = raw_value.strip()
        if _is_valid_directive_field(field):
            # Happy path
            return field, value
        if not raw_value or raw_value[0].isspace():
            # The field is not a known directive, but the colon reads as a
            # field separator (it ends the line or is followed by
            # whitespace), so we keep the "<field>:<value>" interpretation
            # and treat the line as an unknown directive.
            return field, value

    # There is no colon separator, or the field found is not a known
    # directive and its colon does not read as a field separator. We will
    # be generous here and give the line a second chance, parsing it as a
    # whitespace-separated "<field> <value>" directive. This also salvages
    # lines whose value contains a colon of its own, e.g.
    # "Sitemap https://example.com/sitemap.xml".
    words = line.split()
    for word_count in range(1, _MAX_DIRECTIVE_WORDS + 1):
        # Trying "<multiword> <field> <value>"
        candidate = " ".join(words[:word_count]).lower()
        if _is_valid_directive_field(candidate):
            return candidate, " ".join(words[word_count:])

    if field is None:
        return None
    # Salvage failed; keep the unknown "<field>:<value>" directive.
    return field, value


class Protego:
    def __init__(self) -> None:
        # A dict mapping user agents (specified in robots.txt) to rule sets.
        self._user_agents: dict[str, _RuleSet] = {}

        # Preferred host specified in the robots.txt
        self._host: str | None = None

        # A list of sitemaps specified in the robots.txt
        self._sitemap_list: list[str] = []

        # A memoization table mapping user agents (used in queries) to matched rule sets.
        self._matched_rule_set: dict[str, _RuleSet | None] = {}

        # URL patterns by directive value, shared across rule sets.
        self._url_patterns: dict[str, _URLPattern] = {}

        self._total_line_seen = 0
        self._total_directive_seen = 0

    @classmethod
    def parse(cls, content: str) -> Self:
        o = cls()
        if not isinstance(content, str):
            raise TypeError(f"Protego.parse expects str, got {type(content).__name__}")
        o._parse_robotstxt(content)
        return o

    def _parse_robotstxt(self, content: str) -> None:
        # Ignore one leading UTF-8 byte order mark, matching Google's parser:
        # https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec
        content = content.removeprefix("\ufeff")
        lines = content.splitlines()

        # A list containing rule sets corresponding to user
        # agents of the current record group.
        current_rule_sets: list[_RuleSet] = []

        # Last encountered rule irrespective of whether it was valid or not.
        previous_rule_field = None

        for line in lines:
            self._total_line_seen += 1

            # The raw line, kept so that rules can point back at their source.
            raw_line = line.strip()

            # Remove the comment portion of the line
            hash_pos = line.find("#")
            if hash_pos != -1:
                line = line[0:hash_pos].strip()

            # Whitespace at the beginning and at the end of the line is ignored.
            line = line.strip()
            if not line:
                continue

            parsed = _extract_directive(line)
            if parsed is None:
                continue
            field, value = parsed

            # A user agent line, even one without a usable value, ends the
            # previous record group.
            if (
                field in _USER_AGENT_DIRECTIVE
                and previous_rule_field is not None
                and previous_rule_field not in _USER_AGENT_DIRECTIVE
            ):
                current_rule_sets = []

            # Sitemap and Host are site-wide directives and don't matter for
            # record grouping.
            if field not in _SITE_WIDE_DIRECTIVES:
                previous_rule_field = field

            # Ignore rules with no value part (e.g. "Disallow: ", "Allow: ").
            if not value:
                continue

            # Ignore rules without a corresponding user agent, except
            # site-wide directives which need none.
            if (
                not current_rule_sets
                and field not in _USER_AGENT_DIRECTIVE
                and field not in _SITE_WIDE_DIRECTIVES
            ):
                logger.debug(
                    f"Rule at line {self._total_line_seen} without any user agent to enforce it on."
                )
                continue

            self._total_directive_seen += 1

            if field in _USER_AGENT_DIRECTIVE:
                # Wildcards are not supported in the user agent values.
                # We will be generous here and remove all the wildcards.
                user_agent = value.strip().lower()
                user_agent_without_asterisk = None
                if user_agent != "*" and "*" in user_agent:
                    user_agent_without_asterisk = user_agent.replace("*", "")

                user_agents = [user_agent, user_agent_without_asterisk]
                for ua in user_agents:
                    if not ua:
                        continue
                    # See if this user agent is encountered before, if so merge these rules into it.
                    rule_set = self._user_agents.get(ua, None)
                    if rule_set and rule_set not in current_rule_sets:
                        current_rule_sets.append(rule_set)

                    if not rule_set:
                        rule_set = _RuleSet(self)
                        rule_set.user_agent = ua
                        self._user_agents[ua] = rule_set
                        current_rule_sets.append(rule_set)

            elif field in _ALLOW_DIRECTIVE:
                source = RuleSource(self._total_line_seen, raw_line)
                for rule_set in current_rule_sets:
                    rule_set.allow(value, source)

            elif field in _DISALLOW_DIRECTIVE:
                source = RuleSource(self._total_line_seen, raw_line)
                for rule_set in current_rule_sets:
                    rule_set.disallow(value, source)

            elif field in _SITEMAP_DIRECTIVE:
                self._sitemap_list.append(value)

            elif field in _CRAWL_DELAY_DIRECTIVE:
                for rule_set in current_rule_sets:
                    rule_set.crawl_delay = value

            elif field in _REQUEST_RATE_DIRECTIVE:
                for rule_set in current_rule_sets:
                    rule_set.request_rate = value

            elif field in _HOST_DIRECTIVE:
                self._host = value

            elif field in _VISIT_TIME_DIRECTIVE:
                for rule_set in current_rule_sets:
                    rule_set.visit_time = value

        for rule_set in self._user_agents.values():
            rule_set.finalize_rules()

    def _get_matching_rule_set(self, user_agent: str) -> _RuleSet | None:
        """Return the rule set with highest matching score."""
        if not self._user_agents:
            return None

        if user_agent in self._matched_rule_set:
            return self._matched_rule_set[user_agent]
        score_rule_set_pairs = (
            (rs.applies_to(user_agent), rs) for rs in self._user_agents.values()
        )
        match_score, matched_rule_set = max(score_rule_set_pairs, key=lambda p: p[0])

        if not match_score:
            self._matched_rule_set[user_agent] = None
            return None
        self._matched_rule_set[user_agent] = matched_rule_set
        return matched_rule_set

    def _explain_user_agent(self, user_agent: str) -> UserAgentExplanation:
        """Explain which user agent group a query resolves to.

        The group itself is decided by :meth:`_get_matching_rule_set`, the
        same selection that :meth:`can_fetch` uses; this method only adds
        the reasoning around it.
        """
        matched_rule_set = self._get_matching_rule_set(user_agent)
        candidates = tuple(
            (rule_set.user_agent or "", rule_set.applies_to(user_agent))
            for rule_set in self._user_agents.values()
        )
        if matched_rule_set is None:
            reason = (
                "no group's product token matches this user agent; "
                "the default rule applies"
            )
            return UserAgentExplanation(user_agent, None, 0, candidates, reason)

        assert matched_rule_set.user_agent is not None
        group = matched_rule_set.user_agent
        score = matched_rule_set.applies_to(user_agent)
        tied = [
            name
            for name, candidate_score in candidates
            if candidate_score == score and name != group
        ]
        if group == "*":
            reason = (
                "the wildcard group '*' is the only match (score 1); "
                "an unnamed crawler falls back to it"
            )
        elif tied:
            reason = (
                f"group '{group}' ties on the longest product-token match "
                f"(score {score}) with {', '.join(repr(name) for name in tied)}; "
                "the earliest declared group wins"
            )
        else:
            reason = (
                f"product token '{group}' is the longest match in this user "
                f"agent at a token boundary (score {score}), so its group wins"
            )
        return UserAgentExplanation(user_agent, group, score, candidates, reason)

    @staticmethod
    def _normalization_notes(url: str, normalized: str) -> tuple[str, ...]:
        """Describe how a URL was normalized before rule matching."""
        notes: list[str] = []
        if "://" in url:
            notes.append(
                "the scheme, host and fragment are dropped; only the path "
                "and query are matched"
            )
        elif not url.startswith("/"):
            notes.append("a relative URL is taken to start at the site root")
        if urlparse(url).fragment:
            notes.append("the fragment is dropped; rules never match against it")
        if "%" in url:
            notes.append(
                "percent-escapes are decoded and re-encoded canonically so "
                "equivalent spellings compare equal"
            )
        if not notes and url != normalized:
            notes.append(
                "the URL is percent-encoded for comparison against rule patterns"
            )
        return tuple(notes)

    def can_fetch(self, url: str, user_agent: str) -> bool:
        """Return True if the user agent can fetch the URL, otherwise return False."""
        if "/robots.txt" in url and urlparse(url).path == "/robots.txt":
            return True
        matched_rule_set = self._get_matching_rule_set(user_agent)
        if not matched_rule_set:
            return True
        return matched_rule_set.can_fetch(url)

    def explain_fetch(
        self,
        url: str,
        user_agent: str,
        *,
        other_rules_budget: int = DEFAULT_OTHER_RULES_BUDGET,
    ) -> FetchExplanation:
        """Explain why :meth:`can_fetch` gives the answer it gives.

        The returned :class:`FetchExplanation` reports the user agent group
        that applies, the rule that decided the outcome with the number and
        text of its source line, and the other rules that also match the URL
        (capped at *other_rules_budget*). The winning rule is the one the
        real match loop picks, so the decision is always identical to
        :meth:`can_fetch` for the same arguments.
        """
        if other_rules_budget < 0:
            raise ValueError("other_rules_budget must be non-negative")
        normalized_url = _quote_path(url)
        normalization = self._normalization_notes(url, normalized_url)
        if "/robots.txt" in url and urlparse(url).path == "/robots.txt":
            return FetchExplanation(
                url,
                user_agent,
                allowed=True,
                normalized_url=normalized_url,
                normalization=normalization,
                reason="robots.txt itself is always fetchable, "
                "no rules are consulted",
                robots_txt_allowed=True,
            )

        agent_explanation = self._explain_user_agent(user_agent)
        matched_rule_set = self._get_matching_rule_set(user_agent)
        if matched_rule_set is None:
            return FetchExplanation(
                url,
                user_agent,
                allowed=True,
                normalized_url=normalized_url,
                normalization=normalization,
                user_agent_explanation=agent_explanation,
                reason="no user agent group applies, so the default rule "
                "allows the fetch",
            )

        normalized_url, winner, others, truncated = matched_rule_set.explain(
            url, other_rules_budget
        )
        if winner is None:
            reason = (
                "no rule in the group matches the URL, so the default rule "
                "allows the fetch"
            )
            allowed = True
        else:
            allowed = winner.field == "allow"
            kind = "Allow" if allowed else "Disallow"
            tied_disallow = any(
                other.field == "disallow"
                and len(other.pattern) == len(winner.pattern)
                for other in others
            )
            if allowed and tied_disallow:
                reason = (
                    "rules are tried longest-pattern first; "
                    f"'{winner.pattern}' ties on length with a Disallow "
                    "match, and at equal length Allow wins"
                )
            else:
                reason = (
                    "rules are tried longest-pattern first; "
                    f"'{winner.pattern}' is the first match, and it is "
                    f"a {kind} rule"
                )
        return FetchExplanation(
            url,
            user_agent,
            allowed=allowed,
            normalized_url=normalized_url,
            normalization=normalization,
            user_agent_explanation=agent_explanation,
            winning_rule=winner,
            reason=reason,
            other_rules=tuple(others),
            other_rules_truncated=truncated,
        )

    def crawl_delay(self, user_agent: str) -> float | None:
        """Return the crawl delay specified for the user agent as a float.
        If nothing is specified, return None.
        """
        matched_rule_set = self._get_matching_rule_set(user_agent)
        if not matched_rule_set:
            return None
        return matched_rule_set.crawl_delay

    def request_rate(self, user_agent: str) -> RequestRate | None:
        """Return the request rate specified for the user agent as a named tuple
        RequestRate(requests, seconds, start_time, end_time). If nothing is
        specified, return None.
        """
        matched_rule_set = self._get_matching_rule_set(user_agent)
        if not matched_rule_set:
            return None
        return matched_rule_set.request_rate

    def visit_time(self, user_agent: str) -> VisitTime | None:
        """Return the visit time specified for the user agent as a named tuple
        VisitTime(start_time, end_time). If nothing is specified, return None.
        """
        matched_rule_set = self._get_matching_rule_set(user_agent)
        if not matched_rule_set:
            return None
        return matched_rule_set.visit_time

    @property
    def sitemaps(self) -> Iterator[str]:
        """Get an iterator containing links to sitemaps specified."""
        return iter(self._sitemap_list)

    @property
    def preferred_host(self) -> str | None:
        """Get the preferred host."""
        return self._host
