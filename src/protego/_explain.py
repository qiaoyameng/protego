from __future__ import annotations

from dataclasses import dataclass, field

#: Default cap on the other matching rules reported alongside the winner.
DEFAULT_OTHER_RULES_BUDGET = 10


@dataclass(frozen=True)
class RuleSource:
    """Where a rule that took part in matching came from.

    A single robots.txt line can yield more than one rule (the ``$`` end
    anchor and the ``index.html`` convention both do), which is why
    *derivation* describes how the rule relates to the source line.
    """

    line_number: int
    line_text: str
    derivation: str = ""


@dataclass(frozen=True)
class MatchedRule:
    """A rule that matched the normalized URL during the actual match loop."""

    field: str
    pattern: str
    source: RuleSource
    is_winner: bool = False


@dataclass(frozen=True)
class UserAgentExplanation:
    """How the user agent group used for the decision was selected."""

    requested_user_agent: str
    group: str | None
    match_score: int
    candidates: tuple[tuple[str, int], ...]
    reason: str


@dataclass(frozen=True)
class FetchExplanation:
    """The full reasoning behind an :meth:`Protego.explain_fetch` decision.

    The decision is always identical to what :meth:`Protego.can_fetch`
    returns for the same arguments: the winning rule is the one the real
    match loop picks, while the other matching rules are found by scanning
    the same rule list with the same per-rule comparison.
    """

    url: str
    user_agent: str
    allowed: bool
    normalized_url: str
    normalization: tuple[str, ...] = field(default=())
    user_agent_explanation: UserAgentExplanation | None = None
    winning_rule: MatchedRule | None = None
    reason: str = ""
    other_rules: tuple[MatchedRule, ...] = ()
    other_rules_truncated: bool = False
    robots_txt_allowed: bool = False

    def to_text(self) -> str:
        """Render the explanation as human-readable plain text."""
        lines = [
            f"URL: {self.url}",
            f"User-agent: {self.user_agent}",
            f"Decision: {'allow' if self.allowed else 'disallow'}",
        ]
        if self.normalization:
            lines.append(f"Normalized URL: {self.normalized_url}")
            lines.extend(f"  - {note}" for note in self.normalization)
        else:
            lines.append(f"Normalized URL: {self.normalized_url} (no changes)")

        if self.robots_txt_allowed:
            lines.append(f"Reason: {self.reason}")
            return "\n".join(lines)

        agent = self.user_agent_explanation
        if agent is not None:
            lines.append(f"User-agent group: {agent.group or '(none)'}")
            lines.append(f"  - {agent.reason}")
            if agent.candidates:
                scored = ", ".join(
                    f"{name}={score}" for name, score in agent.candidates
                )
                lines.append(f"  - group scores: {scored}")

        winner = self.winning_rule
        if winner is not None:
            kind = "Allow" if winner.field == "allow" else "Disallow"
            lines.append(
                f"Winning rule: {kind}: {winner.pattern} "
                f"(line {winner.source.line_number})"
            )
            lines.append(f"  source: {winner.source.line_text}")
            if winner.source.derivation:
                lines.append(f"  derivation: {winner.source.derivation}")
        lines.append(f"Reason: {self.reason}")

        if self.other_rules:
            lines.append("Other matching rules:")
            for rule in self.other_rules:
                kind = "Allow" if rule.field == "allow" else "Disallow"
                derivation = rule.source.derivation
                suffix = f" — {derivation}" if derivation else ""
                lines.append(
                    f"  - {kind}: {rule.pattern} "
                    f"(line {rule.source.line_number}){suffix}"
                )
            if self.other_rules_truncated:
                lines.append(
                    f"  ... and more (truncated to {len(self.other_rules)} rules)"
                )
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_text()
