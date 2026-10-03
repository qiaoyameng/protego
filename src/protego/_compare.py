"""Compare the crawl policies of two ``robots.txt`` versions.

Instead of probing a handful of sample URLs, :func:`compare_policies`
compiles the rules that apply to a given user agent in each version into
finite automata and explores the product state space, so it either proves
the two versions equivalent or returns a concrete counterexample.

Compared semantics (identical to :meth:`Protego.can_fetch`):

-   rules are tried longest (normalized) pattern first, and on a tie an
    ``Allow`` rule wins over a ``Disallow`` rule;
-   the first matching rule decides, and a URL with no matching rule is
    allowed;
-   ``/robots.txt`` itself is always allowed, whatever the rules say.

Supported pattern syntax: plain path literals, ``*`` wildcards and a
trailing ``$`` anchor, i.e. everything the parser itself supports.

Character domain and percent-encoding
-------------------------------------

Paths are compared in normalized form, i.e. after the same normalization
that :meth:`Protego.can_fetch` applies to its input. A normalized path:

-   starts with a single ``/``;
-   contains only characters that percent-encoding leaves alone
    (letters, digits and ``_.-~/=``) and ``%``;
-   spells every valid ``%XX`` escape with uppercase hex digits.

Because the comparison happens after normalization, ``%41`` and ``A``
are the same character, while ``%2F`` stays an escape and is matched as
the three characters ``%``, ``2`` and ``F``. Any character that does not
occur literally in the rules is indistinguishable from any other for
matching purposes, so they are all represented by a single fresh
character during the exploration.

State budget
------------

The exploration is breadth-first over the product of the pattern
automata, so a reported counterexample is a shortest one. The number of
product states is bounded by ``max_states``; if the budget is exhausted
the result is ``"undetermined"`` (nothing was proven), never
``"equivalent"``.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from itertools import product
from typing import TYPE_CHECKING

from ._utils import _quote_path

if TYPE_CHECKING:
    from ._protego import Protego
    from ._urlpattern import _URLPattern

__all__ = ["PolicyComparison", "brute_force_difference", "compare_policies"]

#: Statuses of a :class:`PolicyComparison`.
EQUIVALENT = "equivalent"
DIFFERENT = "different"
UNDETERMINED = "undetermined"

#: Characters that percent-encoding leaves alone in a path.
_SAFE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~/="
)

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_LOWER_HEX_CHARS = frozenset("abcdef")

# Candidates for the representative of "any character not used by the
# rules". It must normalize to itself, must not be "%" (so that it cannot
# open an escape) and must not be a hexadecimal digit (so that it stays
# unambiguous next to a "%" in a candidate path).
_REPRESENTATIVE_CANDIDATES = "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ_.-~="

# Normalization tracker states: a normalized path never contains a valid
# %XX escape spelled with a lowercase hex digit.
_T_NONE = 0
_T_PERCENT = 1
_T_HEX_OK = 2
_T_HEX_LOWER = 3

# Token standing for "any character not literally present in the rules".
_OTHER = object()


@dataclass(frozen=True)
class PolicyComparison:
    """Outcome of :func:`compare_policies`.

    ``status`` is one of:

    -   ``"equivalent"``: both versions allow exactly the same normalized
        paths for the user agent (within the documented character domain);
    -   ``"different"``: ``path`` is a shortest normalized path on which
        the versions disagree, and ``old_verdict`` / ``new_verdict`` are
        its actual outcomes under each version;
    -   ``"undetermined"``: the state budget was exhausted before a
        verdict could be proven; ``reason`` says why.
    """

    status: str
    user_agent: str
    path: str | None = None
    old_verdict: bool | None = None
    new_verdict: bool | None = None
    states_explored: int = 0
    reason: str | None = None


class _PatternNFA:
    """NFA accepting the URLs a single rule pattern matches."""

    __slots__ = ("accept", "any_trans", "char_trans", "start")

    def __init__(self) -> None:
        # (state, char) -> target states
        self.char_trans: dict[tuple[int, str], frozenset[int]] = {}
        # state -> target states, taken on any character
        self.any_trans: dict[int, frozenset[int]] = {}
        self.accept: frozenset[int] = frozenset()
        self.start = 0

    def _add_char(self, state: int, char: str, target: int) -> None:
        key = (state, char)
        self.char_trans[key] = self.char_trans.get(key, frozenset()) | {target}

    def _add_any(self, state: int, target: int) -> None:
        self.any_trans[state] = self.any_trans.get(state, frozenset()) | {target}


def _build_literal(nfa: _PatternNFA, literal: str, *, anchored: bool) -> None:
    for index, char in enumerate(literal):
        nfa._add_char(index, char, index + 1)
    nfa.accept = frozenset({len(literal)})
    if not anchored:
        nfa._add_any(len(literal), len(literal))


def _compile_pattern(pattern: _URLPattern) -> _PatternNFA:
    """Compile a normalized rule pattern into an NFA over the whole URL.

    The NFA consumes the whole (normalized) URL and accepts exactly when
    the pattern matches it, mirroring ``_URLPattern.match``.
    """
    nfa = _PatternNFA()
    text = pattern._pattern
    if not pattern._contains_asterisk:
        if pattern._contains_dollar:
            _build_literal(nfa, text[:-1], anchored=True)
        else:
            _build_literal(nfa, text, anchored=False)
        return nfa

    ends_with_dollar = text.endswith("$")
    if ends_with_dollar:
        text = text[:-1]
    parts = re.sub(r"\*+", "*", text).split("*")

    state = 0
    for char in parts[0]:
        nfa._add_char(state, char, state + 1)
        state += 1
    for part in parts[1:]:
        # A "*" matches any sequence, including an empty one.
        nfa._add_any(state, state)
        for char in part:
            nfa._add_char(state, char, state + 1)
            state += 1
    if not ends_with_dollar:
        # Without a trailing "$" anything may follow the match.
        nfa._add_any(state, state)
    nfa.accept = frozenset({state})
    return nfa


def _robots_txt_nfa() -> _PatternNFA:
    """NFA for the "/robots.txt is always allowed" carve-out.

    Covers the exact path and any query variant, which normalizes to a
    "/robots.txt%3F" prefix.
    """
    nfa = _PatternNFA()
    state = 0
    for char in "/robots.txt":
        nfa._add_char(state, char, state + 1)
        state += 1
    accepts = {state}
    for char in "%3F":
        nfa._add_char(state, char, state + 1)
        state += 1
    nfa._add_any(state, state)
    accepts.add(state)
    nfa.accept = frozenset(accepts)
    return nfa


def _tracker_next(tracker: int, char: str) -> int | None:
    """Advance the normalization tracker, or return None if adding ``char``
    would leave the domain of normalized paths."""
    if tracker == _T_NONE:
        return _T_PERCENT if char == "%" else _T_NONE
    if tracker == _T_PERCENT:
        if char == "%":
            return _T_PERCENT
        if char in _LOWER_HEX_CHARS:
            return _T_HEX_LOWER
        if char in _HEX_CHARS:
            return _T_HEX_OK
        return _T_NONE
    # A full %XX escape is only normalized when uppercase.
    if char == "%":
        return _T_PERCENT
    if char in _HEX_CHARS:
        if tracker == _T_HEX_LOWER or char in _LOWER_HEX_CHARS:
            return None
        return _T_NONE
    return _T_NONE


def _matched_rules(protego: Protego, user_agent: str) -> list[tuple[str, _URLPattern]]:
    """Return the (field, pattern) rules that decide for ``user_agent``,
    in decision order: longest pattern first, allow before disallow on
    ties, exactly as ``_RuleSet.can_fetch`` applies them."""
    rule_set = protego._get_matching_rule_set(user_agent)
    if rule_set is None:
        return []
    rules = [(rule.field, rule.value) for rule in rule_set._rules]
    rules.sort(key=lambda r: (r[1].priority, r[0] == "allow"), reverse=True)
    return rules


def _pick_representative(alphabet: set[str]) -> str | None:
    for char in _REPRESENTATIVE_CANDIDATES:
        if char not in alphabet:
            return char
    return None


def compare_policies(
    old: Protego,
    new: Protego,
    user_agent: str,
    *,
    max_states: int = 50_000,
) -> PolicyComparison:
    """Compare the crawl policies of two parsed ``robots.txt`` versions
    for ``user_agent``.

    Returns a :class:`PolicyComparison`; see its documentation and the
    module docstring for the exact semantics, the supported character
    domain and the meaning of the state budget.
    """
    if max_states < 1:
        raise ValueError("max_states must be at least 1")

    old_rules = _matched_rules(old, user_agent)
    new_rules = _matched_rules(new, user_agent)

    nfas: list[_PatternNFA] = []
    nfa_index: dict[str, int] = {}

    def index_for(pattern: _URLPattern) -> int:
        key = pattern._pattern
        if key not in nfa_index:
            nfa_index[key] = len(nfas)
            nfas.append(_compile_pattern(pattern))
        return nfa_index[key]

    # The "/robots.txt" carve-out outranks every rule in both versions.
    robots_index = 0
    nfas.append(_robots_txt_nfa())

    old_compiled = [("allow", robots_index)]
    old_compiled += [(field, index_for(p)) for field, p in old_rules]
    new_compiled = [("allow", robots_index)]
    new_compiled += [(field, index_for(p)) for field, p in new_rules]

    alphabet: set[str] = set()
    for nfa in nfas:
        alphabet.update(char for _, char in nfa.char_trans)
    representative = _pick_representative(alphabet)
    if representative is None:
        return PolicyComparison(
            UNDETERMINED,
            user_agent,
            reason="no fresh character left to represent characters "
            "that do not occur in the rules",
        )
    # Prefer readable counterexamples: try "%" only after every other
    # character, and the fresh representative last.
    tokens: list[str | object] = sorted(
        alphabet, key=lambda char: (char == "%", char)
    ) + [_OTHER]

    def verdict(
        compiled: list[tuple[str, int]], subsets: tuple[frozenset[int], ...]
    ) -> bool:
        for field, index in compiled:
            if nfas[index].accept & subsets[index]:
                return field == "allow"
        return True

    def step(
        state: tuple[int, tuple[frozenset[int], ...]], token: str | object
    ) -> tuple[int, tuple[frozenset[int], ...]] | None:
        tracker, subsets = state
        char = representative if token is _OTHER else token
        tracker = _tracker_next(tracker, char)  # type: ignore[arg-type]
        if tracker is None:
            return None
        next_subsets = []
        for nfa, subset in zip(nfas, subsets):
            reached: set[int] = set()
            for nfa_state in subset:
                reached |= nfa.any_trans.get(nfa_state, frozenset())
                if token is not _OTHER:
                    reached |= nfa.char_trans.get(
                        (nfa_state, token),  # type: ignore[arg-type]
                        frozenset(),
                    )
            next_subsets.append(frozenset(reached))
        return tracker, tuple(next_subsets)

    start = step((_T_NONE, tuple(frozenset({nfa.start}) for nfa in nfas)), "/")
    assert start is not None
    # state -> (parent state, token, depth); None marks the start.
    visited: dict[
        tuple[int, tuple[frozenset[int], ...]],
        tuple[tuple[int, tuple[frozenset[int], ...]], str | object, int] | None,
    ] = {start: None}
    queue = deque([start])

    while queue:
        state = queue.popleft()
        old_verdict = verdict(old_compiled, state[1])
        new_verdict = verdict(new_compiled, state[1])
        if old_verdict != new_verdict:
            path_tokens: list[str | object] = []
            cursor = state
            while visited[cursor] is not None:
                entry = visited[cursor]
                assert entry is not None
                parent, token, _ = entry
                path_tokens.append(token)
                cursor = parent
            path = "/" + "".join(
                representative if token is _OTHER else token  # type: ignore[misc]
                for token in reversed(path_tokens)
            )
            return PolicyComparison(
                DIFFERENT,
                user_agent,
                path=path,
                old_verdict=old.can_fetch(path, user_agent),
                new_verdict=new.can_fetch(path, user_agent),
                states_explored=len(visited),
            )
        if len(visited) >= max_states:
            return PolicyComparison(
                UNDETERMINED,
                user_agent,
                states_explored=len(visited),
                reason=f"state budget of {max_states} exhausted",
            )
        entry = visited[state]
        depth = 0 if entry is None else entry[2] + 1
        for token in tokens:
            # A normalized path never starts with "//".
            if depth == 0 and token == "/":
                continue
            next_state = step(state, token)
            if next_state is None or next_state in visited:
                continue
            visited[next_state] = (state, token, depth)
            queue.append(next_state)

    return PolicyComparison(EQUIVALENT, user_agent, states_explored=len(visited))


def brute_force_difference(
    old: Protego,
    new: Protego,
    user_agent: str,
    *,
    max_length: int,
    alphabet: list[str] | None = None,
) -> tuple[str, bool, bool] | None:
    """Independently enumerate normalized paths up to ``max_length``
    characters and return the first ``(path, old_verdict, new_verdict)``
    on which the versions disagree, or None.

    This is a plain exhaustive check through the public ``can_fetch``
    API, meant to cross-validate :func:`compare_policies` on small rule
    sets. If ``alphabet`` is omitted, the characters occurring in the
    applicable rules plus one fresh character are used.
    """
    if alphabet is None:
        chars: set[str] = set()
        for protego in (old, new):
            for _, pattern in _matched_rules(protego, user_agent):
                chars.update(pattern._pattern.replace("*", "").rstrip("$"))
        chars &= _SAFE_CHARS | {"%"}
        representative = _pick_representative(chars)
        if representative is None:
            raise ValueError("no fresh character available for the alphabet")
        alphabet = sorted(chars) + [representative]
    for length in range(max_length + 1):
        for tail in product(alphabet, repeat=length):
            path = "/" + "".join(tail)
            if _quote_path(path) != path:
                continue
            old_verdict = old.can_fetch(path, user_agent)
            new_verdict = new.can_fetch(path, user_agent)
            if old_verdict != new_verdict:
                return path, old_verdict, new_verdict
    return None
