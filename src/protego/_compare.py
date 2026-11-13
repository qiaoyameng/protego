from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum

from ._automaton import BudgetExceeded, DFA, _NFABuilder, determinize
from ._protego import Protego
from ._ruleset import _RuleSet
from ._urlpattern import _EXACT, _PREFIX, _WILDCARD, _FlatRule
from ._utils import _quote_path


class Relation(StrEnum):
    """Outcome of comparing two robots.txt policies for one user agent."""

    EQUIVALENT = "equivalent"
    STRICTER = "stricter"
    LOOSER = "looser"
    BOTH = "both"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ComparisonBudget:
    """Limits that keep the analysis from running away on pathological rules."""

    max_rule_states: int = 5_000
    max_product_states: int = 50_000


@dataclass(frozen=True)
class Witness:
    """A concrete URL on which the two policies make different decisions."""

    url: str
    old_allowed: bool
    new_allowed: bool


@dataclass(frozen=True)
class PolicyComparison:
    """Result of comparing two robots.txt policies for one user agent."""

    relation: Relation
    user_agent: str
    old_group: str | None
    new_group: str | None
    witnesses: tuple[Witness, ...] = ()
    unknown_reason: str | None = None
    states_explored: int = 0


# Characters that percent-encoding always leaves untouched. They make safe
# concrete representatives of the "any other character" alphabet class.
_UNRESERVED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"

_WITNESS_BASE_URL = "https://comparison.invalid"


def _flat_rules(rule_set: _RuleSet) -> list[_FlatRule]:
    """Return the rules in the exact order the can_fetch match loop uses."""
    rule_set._build_index()
    return list(rule_set._flat_rules)


def _literal_characters(rules: list[_FlatRule]) -> set[str]:
    """Collect every literal character a rule pattern can match."""
    characters: set[str] = set()
    for kind, data, _ in rules:
        if kind in (_PREFIX, _EXACT):
            characters.update(data)
        else:
            first, _, middle, last, _, _ = data
            characters.update(first)
            for part, _ in middle:
                characters.update(part)
            characters.update(last)
    return characters


def _rule_nfa(kind: int, data: str | tuple) -> tuple[_NFABuilder, int]:
    """Translate one robots.txt glob into an epsilon NFA builder."""
    builder = _NFABuilder()
    node = 0
    if kind == _PREFIX:
        assert isinstance(data, str)
        node = builder.add_literal(0, data)
        node = builder.add_star(node)
    elif kind == _EXACT:
        assert isinstance(data, str)
        node = builder.add_literal(0, data)
    else:
        assert isinstance(data, tuple)
        first, _, middle, last, _, anchored = data
        node = builder.add_literal(0, first)
        for part, _ in middle:
            node = builder.add_star(node)
            node = builder.add_literal(node, part)
        node = builder.add_star(node)
        node = builder.add_literal(node, last)
        if not anchored:
            node = builder.add_star(node)
    return builder, node


def _build_alphabet(
    old_rules: list[_FlatRule], new_rules: list[_FlatRule]
) -> tuple[str, ...]:
    """Build one shared alphabet: a singleton class per literal character.

    Rules only compare literal characters against URL characters, so two
    characters that no rule mentions are indistinguishable and share one
    class, represented by a quote-safe unreserved character.
    """
    # The universe automaton spells out "/robots.txt", whose characters must
    # therefore have alphabet classes of their own.
    literals = (
        _literal_characters(old_rules)
        | _literal_characters(new_rules)
        | set("/robots.txt%0123456789ABCDEFabcdef?#:@")
    )
    representatives = ["/"] + sorted(literals - {"/"})
    rest = next(
        (char for char in _UNRESERVED if char not in literals and char != "/"),
        None,
    )
    if rest is None:
        raise BudgetExceeded("alphabet exhausted: every safe character is used")
    representatives.append(rest)
    return tuple(representatives)


def _build_rule_dfas(
    rules: list[_FlatRule],
    representatives: tuple[str, ...],
    budget: ComparisonBudget,
) -> list[tuple[DFA, bool]]:
    dfas: list[tuple[DFA, bool]] = []
    for kind, data, is_disallow in rules:
        builder, accept = _rule_nfa(kind, data)
        dfa = determinize(
            builder.build(accept), representatives, budget.max_rule_states
        )
        dfas.append((dfa, is_disallow))
    return dfas


def _universe_dfa(representatives: tuple[str, ...]) -> DFA:
    """Accept exactly the normalized-path comparison universe.

    An accepted string is a path that quoting leaves untouched when it
    arrives as the path of a full URL. Slashes (including a leading or a
    repeated ``//``) survive normalization; a percent sign is only part of
    the space when it starts a complete two-hex-digit escape naming a byte
    that quoting re-encodes to itself, while characters that quoting
    rewrites (``?``, ``#``, ``:``, ``@`` and the non-alphabet "rest" class)
    never enter it. The always-allowed ``/robots.txt`` is excluded.
    """
    alphabet_size = len(representatives)
    index = {char: i for i, char in enumerate(representatives)}
    hex_digits = frozenset("0123456789ABCDEFabcdef")
    hex_indices = frozenset(index[char] for char in hex_digits)
    uppercase_hex = frozenset("0123456789ABCDEF")
    forbidden = frozenset(index[char] for char in "?#:@")
    rest_index = alphabet_size - 1
    robots = "robots.txt"

    # Byte values 0xHH for which "%HH" is a stable spelling: quoting always
    # re-encodes these bytes, and "%25"/"%2F" stay because "/" and "%" are
    # kept from decoding.
    stable_bytes = frozenset(
        int(h, 16)
        for h in (
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F "
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F "
            "20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2F "
            "3A 3B 3C 3E 3F 40 5B 5C 5D 5E 60 7B 7C 7D 7F"
        ).split()
    )

    # Fixed states: start, a live path, a dead string and just-read "%".
    # One pending state per first (uppercase) hex digit remembers it while
    # the second digit is read. A lowercase a-f starts an escape too, but it
    # can never yield a stable completed escape (normalization uppercases
    # it), so those share one lowercase-pending state. Pending states are
    # accepting because a truncated escape is itself a valid, stable path.
    start, live, dead, percent_seen = range(4)
    first_digits = sorted(uppercase_hex)
    digit_states = {
        digit: 4 + position for position, digit in enumerate(first_digits)
    }
    lowercase_pending = 4 + len(first_digits)
    after_digit = lowercase_pending + 1
    # Prefix states of "/robots.txt" follow the escape-tracking states.
    prefix_states = list(
        range(after_digit, after_digit + len(robots) + 1)
    )

    transitions: list[list[int]] = []

    start_row = [dead for _ in range(alphabet_size)]
    start_row[index["/"]] = prefix_states[0]
    transitions.append(start_row)

    def base_row(allow_percent: bool) -> list[int]:
        row: list[int] = []
        for i in range(alphabet_size):
            if i in forbidden or i == rest_index:
                row.append(dead)
            elif allow_percent and i == index["%"]:
                row.append(percent_seen)
            else:
                row.append(live)
        return row

    transitions.append(base_row(allow_percent=True))  # live
    transitions.append([dead for _ in range(alphabet_size)])  # dead

    # "%": a hex digit opens an escape candidate; otherwise the percent is
    # literal (e.g. "%z", "%%") and the path stays live.
    percent_seen_row = base_row(allow_percent=True)
    for digit, state in digit_states.items():
        percent_seen_row[index[digit]] = state
    for lowercase in "abcdef":
        percent_seen_row[index[lowercase]] = lowercase_pending
    transitions.append(percent_seen_row)

    # "%H" with an uppercase first digit: the second hex digit completes
    # "%HH", accepted only when uppercase and naming a stable byte.
    for first in first_digits:
        row = base_row(allow_percent=True)
        for second in uppercase_hex:
            byte = int(first + second, 16)
            row[index[second]] = live if byte in stable_bytes else dead
        for lowercase in "abcdef":
            row[index[lowercase]] = dead
        transitions.append(row)
    # A lowercase first digit means the completed spelling is rewritten
    # regardless of the byte, so any hex second digit kills the path.
    lowercase_row = base_row(allow_percent=True)
    for hex_index in hex_indices:
        lowercase_row[hex_index] = dead
    transitions.append(lowercase_row)

    for position in range(len(robots)):
        row = base_row(allow_percent=True)
        row[index[robots[position]]] = prefix_states[position + 1]
        transitions.append(row)
    # The completed "/robots.txt" prefix and all its continuations are out.
    transitions.append([dead for _ in range(alphabet_size)])

    accepting = {live, percent_seen, lowercase_pending, *digit_states.values()}
    accepting.update(prefix_states[:-1])
    return DFA(
        representatives,
        tuple(tuple(row) for row in transitions),
        frozenset(accepting),
    )


def _decide(rules: list[tuple[DFA, bool]], states: tuple[int, ...]) -> bool:
    """First matching rule decides, mirroring the can_fetch match loop."""
    for (dfa, is_disallow), state in zip(rules, states, strict=True):
        if state in dfa.accepting:
            return not is_disallow
    return True


def _make_witness(
    path: str,
    old: Protego,
    new: Protego,
    user_agent: str,
    expected_old: bool,
    expected_new: bool,
) -> Witness | None:
    """Cross-check a witness with the real can_fetch on both policies."""
    # The universe automaton models paths as quoting leaves them inside a
    # full URL: a leading "//" is a path there, though the bare string reads
    # it as an authority. Use the full-URL form, exactly like can_fetch.
    url = _WITNESS_BASE_URL + path
    if _quote_path(url) != path:
        return None
    old_allowed = old.can_fetch(url, user_agent)
    new_allowed = new.can_fetch(url, user_agent)
    if old_allowed != expected_old or new_allowed != expected_new:
        msg = (
            "internal automaton disagrees with can_fetch for "
            f"{path!r}: {old_allowed=} {new_allowed=} "
            f"{expected_old=} {expected_new=}"
        )
        raise RuntimeError(msg)
    return Witness(url=url, old_allowed=old_allowed, new_allowed=new_allowed)


def _matched_rule_set(
    parser: Protego, user_agent: str
) -> tuple[_RuleSet | None, str | None]:
    rule_set = parser._get_matching_rule_set(user_agent)
    if rule_set is None:
        return None, None
    return rule_set, rule_set.user_agent


def compare_policies(
    old: Protego,
    new: Protego,
    user_agent: str,
    *,
    budget: ComparisonBudget | None = None,
) -> PolicyComparison:
    """Compare two parsed robots.txt policies for one user agent.

    The analysis works on the exact rule sets, escaping and rule precedence
    that ``can_fetch`` uses, and explores the whole URL path space through
    deterministic automata rather than random URL samples. Every reported
    witness is re-checked with ``can_fetch`` on both policies.
    """
    budget = budget or ComparisonBudget()
    old_rule_set, old_group = _matched_rule_set(old, user_agent)
    new_rule_set, new_group = _matched_rule_set(new, user_agent)
    old_rules = _flat_rules(old_rule_set) if old_rule_set is not None else []
    new_rules = _flat_rules(new_rule_set) if new_rule_set is not None else []

    unknown_reason: str | None = None
    try:
        representatives = _build_alphabet(old_rules, new_rules)
        old_dfas = _build_rule_dfas(old_rules, representatives, budget)
        new_dfas = _build_rule_dfas(new_rules, representatives, budget)
        universe = _universe_dfa(representatives)
    except BudgetExceeded as exc:
        return PolicyComparison(
            relation=Relation.UNKNOWN,
            user_agent=user_agent,
            old_group=old_group,
            new_group=new_group,
            unknown_reason=(
                f"analysis budget exhausted while building automata: {exc}"
            ),
        )

    old_count = len(old_dfas)
    start = (
        (0,)
        + tuple(0 for _ in old_dfas)
        + tuple(0 for _ in new_dfas)
    )
    visited = {start}
    paths = {start: ""}
    queue: deque[tuple[int, ...]] = deque([start])

    strict_witness: Witness | None = None
    loose_witness: Witness | None = None
    states_explored = 0

    while queue:
        current = queue.popleft()
        states_explored += 1
        if states_explored > budget.max_product_states:
            unknown_reason = (
                f"product automaton exceeded {budget.max_product_states} "
                "reachable states before the whole path space was explored"
            )
            break

        universe_state = current[0]
        old_states = current[1 : 1 + old_count]
        new_states = current[1 + old_count :]
        in_path_space = universe_state in universe.accepting

        if in_path_space:
            old_allowed = _decide(old_dfas, old_states)
            new_allowed = _decide(new_dfas, new_states)
            if old_allowed != new_allowed:
                path = paths[current]
                witness = _make_witness(
                    path,
                    old,
                    new,
                    user_agent,
                    old_allowed,
                    new_allowed,
                )
                if old_allowed and not new_allowed and strict_witness is None:
                    strict_witness = witness
                if not old_allowed and new_allowed and loose_witness is None:
                    loose_witness = witness

        for alphabet_index in range(len(representatives)):
            nxt = (
                universe.transitions[universe_state][alphabet_index],
                *(
                    dfa.transitions[state][alphabet_index]
                    for (dfa, _), state in zip(old_dfas, old_states, strict=True)
                ),
                *(
                    dfa.transitions[state][alphabet_index]
                    for (dfa, _), state in zip(new_dfas, new_states, strict=True)
                ),
            )
            if nxt not in visited:
                if len(visited) >= budget.max_product_states:
                    unknown_reason = (
                        f"product automaton exceeded {budget.max_product_states} "
                        "reachable states before the whole path space was explored"
                    )
                    queue.clear()
                    break
                visited.add(nxt)
                paths[nxt] = paths[current] + representatives[alphabet_index]
                queue.append(nxt)

    witnesses = tuple(
        witness
        for witness in (strict_witness, loose_witness)
        if witness is not None
    )

    if unknown_reason is not None:
        relation = Relation.UNKNOWN
    elif strict_witness is not None and loose_witness is not None:
        relation = Relation.BOTH
    elif strict_witness is not None:
        relation = Relation.STRICTER
    elif loose_witness is not None:
        relation = Relation.LOOSER
    else:
        relation = Relation.EQUIVALENT

    return PolicyComparison(
        relation=relation,
        user_agent=user_agent,
        old_group=old_group,
        new_group=new_group,
        witnesses=witnesses,
        unknown_reason=unknown_reason,
        states_explored=states_explored,
    )


def compare_robotstxt(
    old_content: str,
    new_content: str,
    user_agent: str,
    *,
    budget: ComparisonBudget | None = None,
) -> PolicyComparison:
    """Parse two robots.txt texts and compare their policies for one agent."""
    return compare_policies(
        Protego.parse(old_content),
        Protego.parse(new_content),
        user_agent,
        budget=budget,
    )
