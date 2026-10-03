"""Prove whether two ``robots.txt`` versions enforce the same crawl policy.

:func:`compare_rule_sets` decides whether two rule sets, e.g. those that
:class:`~protego.Protego` selects for a user agent in an old and a new
``robots.txt``, allow and disallow exactly the same paths, without
sampling URLs. When they differ, it returns a shortest differing path
along with the verdict of each version on it, so that a pre-release
check can point at a concrete URL that the new file newly forbids (or
permits). Rules are compared as they are matched: literal prefixes,
``*`` wildcards and trailing ``$`` anchors, with longest-pattern
precedence and ``Allow`` winning ties, so differences caused by
precedence, and not only by added ``Disallow`` lines, are found.

Character domain and percent-encoding
=====================================

The comparison happens in the same normalized path space that
:meth:`protego.Protego.can_fetch` matches rules in (see
``protego._utils._quote_path`` and ``protego._utils._quote_pattern``):

-   Percent-escapes are decoded, except those of ``/`` (``%2F``) and
    ``%`` (``%25``), which stay encoded so that they cannot be confused
    with the literal characters. Anything that is not an unreserved
    character (RFC 3986) or one of ``/``, ``%`` and ``=`` is then
    percent-encoded, and escape hexadecimal is uppercased. Spellings
    such as ``/café`` and ``/caf%C3%A9`` therefore compare equal, on
    either side of a rule.
-   The scheme, authority and fragment of a URL never reach the rules,
    and ``?`` is not part of the normalized alphabet (it is encoded as
    ``%3F``), so compared paths are plain ``/``-rooted strings.
-   Every string that starts with ``/`` is a normalized path that some
    URL normalizes to, including strings starting with ``//`` (which an
    extra ``//`` prefix in the input produces, since a leading ``//``
    is otherwise read as an authority). The search explores exactly
    those strings.
-   In rules, ``*`` matches any sequence of characters and a trailing
    ``$`` anchors the rule to the end of the path; a ``$`` anywhere
    else is an ordinary, percent-encoded character.

How paths are proved equivalent or different
============================================

Every rule is compiled into a small matcher whose state after reading a
path prefix is finite: how much of a literal prefix or exact (``$``)
rule has been consumed, or, for a wildcard rule, which positions of its
literal parts the path could currently be at (a subset construction
over the parts, like an NFA for ``part1.*part2``). The two policies are
then explored together, breadth-first, over product states ``(path, old
states, new states)``:

-   The alphabet is the characters that occur in the normalized rules
    of either version, plus one extra character that stands for every
    other character. This is complete: rule matching only ever compares
    characters for equality, so replacing all characters that appear in
    no rule with a single representative cannot change any match, and
    hence cannot change any verdict.
-   A path is a counterexample when the two sides reach different
    verdicts on it. The verdict among matching rules is the one of the
    longest pattern, ``Allow`` winning ties, exactly as
    ``_RuleSet.finalize_rules`` orders rules. Because the search is
    breadth-first, the first counterexample found is a shortest one,
    reported in normalized form.
-   The product space is finite, so the search terminates.
    ``max_states`` bounds how many product states may be explored; if
    the budget runs out first, the result is ``"unproven"`` rather than
    ``"equivalent"``.

``/robots.txt`` itself is always allowed, mirroring
:meth:`protego.Protego.can_fetch`.

For small rule sets, :func:`enumerate_first_difference` offers an
independent check: it brute-forces paths over a given alphabet and asks
each :class:`~protego.Protego` instance directly, and the test suite
uses it to cross-validate this engine.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Literal, NamedTuple, cast

if TYPE_CHECKING:
    from ._protego import Protego
    from ._ruleset import _RuleSet


_DEFAULT_MAX_STATES = 100_000

# can_fetch() allows /robots.txt whatever the rules say.
_ROBOTS_TXT_PATH = "/robots.txt"

# Characters tried, in order, as the representative of "any character
# that no rule mentions". Each of them appears in normalized paths
# verbatim, so a counterexample built with the representative is a real
# path. (_alphabet falls back to "!" if they are all taken; "!" is
# percent-encoded in real paths, so a counterexample that needs it is a
# search artifact rather than a canonical normalized path.)
_OTHER_CHAR_CANDIDATES = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_.-~/=%"
)

_EMPTY_POSITIONS: frozenset[tuple[int, int]] = frozenset()

# Per-rule match status, all hashable:
# - "prefix" and "exact" rules: ("p", k) while the path read so far is a
#   proper prefix of the literal of length k, then "M" (prefix rule
#   matched) or "H" (exact rule hit its full length) or "D" (can never
#   match again).
# - "wildcard" rules: a frozenset of (part, offset) positions, see
#   _wildcard_closure, or "M" once matched (only possible for unanchored
#   rules, whose match is final).
_State = tuple[object, ...]


class PolicyDiff(NamedTuple):
    """The outcome of :meth:`protego.Protego.compare_policy`.

    ``status`` is one of:

    -   ``"equivalent"``: both versions allow and disallow exactly the
        same paths for the user agent.
    -   ``"different"``: a path on which the verdicts differ was found.
        ``path`` is a shortest such path, in normalized form, and
        ``old_allowed`` and ``new_allowed`` are the verdicts of the old
        and the new version on it.
    -   ``"unproven"``: the state budget (``max_states``) ran out before
        the search finished. The policies may or may not be equivalent;
        ``path`` is ``None``.

    ``states_explored`` is the number of product states the search
    visited, for tuning ``max_states``.
    """

    status: Literal["equivalent", "different", "unproven"]
    path: str | None
    old_allowed: bool | None
    new_allowed: bool | None
    states_explored: int


class _CompiledRule(NamedTuple):
    field: str  # "allow" or "disallow"
    priority: int  # longer patterns win; see _URLPattern.priority
    kind: str  # "prefix", "exact" or "wildcard"
    literal: str  # the literal of "prefix" and "exact" rules
    parts: tuple[str, ...]  # the literal parts of "wildcard" rules
    anchored: bool  # whether a "wildcard" rule ends with "$"


class _CompiledPolicy(NamedTuple):
    # In verdict order: longest pattern first, allow before disallow.
    rules: tuple[_CompiledRule, ...]


def _compile_policy(rule_set: _RuleSet | None) -> _CompiledPolicy:
    if rule_set is None:
        return _CompiledPolicy(())
    rules = []
    for rule in rule_set._rules:
        pattern = rule.value
        if pattern._contains_asterisk:
            compiled = _CompiledRule(
                field=rule.field,
                priority=pattern.priority,
                kind="wildcard",
                literal="",
                parts=tuple(pattern._wildcard_parts),
                anchored=pattern._wildcard_ends_with_dollar,
            )
        elif pattern._contains_dollar:
            compiled = _CompiledRule(
                field=rule.field,
                priority=pattern.priority,
                kind="exact",
                literal=pattern._pattern[:-1],
                parts=(),
                anchored=False,
            )
        else:
            compiled = _CompiledRule(
                field=rule.field,
                priority=pattern.priority,
                kind="prefix",
                literal=pattern._pattern,
                parts=(),
                anchored=False,
            )
        rules.append(compiled)
    # The order _RuleSet.finalize_rules establishes: longest pattern
    # first, allow before disallow on ties.
    rules.sort(key=lambda r: (r.priority, r.field == "allow"), reverse=True)
    return _CompiledPolicy(tuple(rules))


def _wildcard_closure(
    parts: tuple[str, ...], positions: frozenset[tuple[int, int]]
) -> frozenset[tuple[int, int]]:
    """Add (i + 1, 0) for every position (i, len(parts[i])) with i < last.

    A position (i, j) means: the literal parts before part i have been
    matched in order, and the path read so far ends with the first j
    characters of part i.
    """
    closure = set(positions)
    last = len(parts) - 1
    changed = True
    while changed:
        changed = False
        for i, j in tuple(closure):
            if j == len(parts[i]) and i < last and (i + 1, 0) not in closure:
                closure.add((i + 1, 0))
                changed = True
    return frozenset(closure)


def _wildcard_accepts(
    parts: tuple[str, ...], positions: frozenset[tuple[int, int]]
) -> bool:
    """Return whether the positions include a complete match ending here."""
    return (len(parts) - 1, len(parts[-1])) in positions


def _wildcard_initial(rule: _CompiledRule) -> object:
    start = _wildcard_closure(rule.parts, frozenset({(0, 0)}))
    if not rule.anchored and _wildcard_accepts(rule.parts, start):
        return "M"
    return start


def _wildcard_step(rule: _CompiledRule, status: object, char: str) -> object:
    if isinstance(status, str):
        return status  # "M": an unanchored wildcard match is final
    positions = cast("frozenset[tuple[int, int]]", status)
    advanced: set[tuple[int, int]] = set()
    for i, j in positions:
        part = rule.parts[i]
        if j < len(part) and part[j] == char:
            advanced.add((i, j + 1))
        if j == 0 and i > 0:
            # The parts before part i matched at some earlier point, so
            # the scan for part i goes on whatever this character is.
            advanced.add((i, 0))
    if not advanced:
        return _EMPTY_POSITIONS
    next_positions = _wildcard_closure(rule.parts, frozenset(advanced))
    if not rule.anchored and _wildcard_accepts(rule.parts, next_positions):
        return "M"
    return next_positions


def _literal_step(rule: _CompiledRule, status: object, char: str) -> object:
    if isinstance(status, str):
        # "M" and "D" are absorbing; one more character after the full
        # length of an exact rule ("H") overshoots it for good.
        return "D" if status == "H" else status
    index = cast("tuple[str, int]", status)[1]
    if char != rule.literal[index]:
        return "D"
    if index + 1 == len(rule.literal):
        return "M" if rule.kind == "prefix" else "H"
    return ("p", index + 1)


def _initial_status(rule: _CompiledRule) -> object:
    if rule.kind == "wildcard":
        return _wildcard_initial(rule)
    if not rule.literal:
        return "M" if rule.kind == "prefix" else "H"
    return ("p", 0)


def _rule_matched(rule: _CompiledRule, status: object) -> bool:
    if rule.kind == "wildcard":
        if rule.anchored:
            return _wildcard_accepts(
                rule.parts, cast("frozenset[tuple[int, int]]", status)
            )
        return status == "M"
    if rule.kind == "exact":
        return status == "H"
    return status == "M"


def _initial_state(policy: _CompiledPolicy) -> _State:
    return tuple(_initial_status(rule) for rule in policy.rules)


class _Stepper:
    """Compute state transitions of a policy, caching them.

    The same rule statuses and the same states recur constantly during
    the search, so both per-rule and per-state transitions are
    memoized.
    """

    def __init__(self, policy: _CompiledPolicy):
        self._policy = policy
        self._rule_cache: dict[tuple[int, object, str], object] = {}
        self._state_cache: dict[tuple[_State, str], _State] = {}

    def step(self, state: _State, char: str) -> _State:
        key = (state, char)
        result = self._state_cache.get(key)
        if result is None:
            result = tuple(
                self._step_rule(index, status, char)
                for index, status in enumerate(state)
            )
            self._state_cache[key] = result
        return result

    def _step_rule(self, index: int, status: object, char: str) -> object:
        key = (index, status, char)
        result = self._rule_cache.get(key)
        if result is None:
            rule = self._policy.rules[index]
            if rule.kind == "wildcard":
                result = _wildcard_step(rule, status, char)
            else:
                result = _literal_step(rule, status, char)
            self._rule_cache[key] = result
        return result


def _verdict(policy: _CompiledPolicy, state: _State) -> bool:
    """Return whether the policy allows a path that reached *state*."""
    for rule, status in zip(policy.rules, state):
        if _rule_matched(rule, status):
            return rule.field == "allow"
    return True


def _alphabet(old: _CompiledPolicy, new: _CompiledPolicy) -> str:
    """Return the characters the proof explores: every character of the
    normalized rules of both sides, plus one character standing for all
    others."""
    chars: set[str] = set()
    for policy in (old, new):
        for rule in policy.rules:
            chars.update(rule.literal)
            for part in rule.parts:
                chars.update(part)
    other = next((c for c in _OTHER_CHAR_CANDIDATES if c not in chars), None)
    if other is None:  # practically impossible: rules mention 69 characters
        other = "!"
    # Try "/" first, then letters and digits, then the rest, and the
    # representative of all other characters last, so that among the
    # shortest counterexamples the search prefers readable ones.
    ordered = sorted(chars, key=lambda c: (c != "/", not c.isalnum(), c))
    return "".join(ordered) + other


def compare_rule_sets(
    old_rule_set: _RuleSet | None,
    new_rule_set: _RuleSet | None,
    max_states: int = _DEFAULT_MAX_STATES,
) -> PolicyDiff:
    """Compare the crawl policy of two rule sets; see the module docs."""
    if max_states < 1:
        raise ValueError(f"max_states must be at least 1, got {max_states}")
    old = _compile_policy(old_rule_set)
    new = _compile_policy(new_rule_set)
    if old == new:
        return PolicyDiff("equivalent", None, None, None, 0)
    alphabet = _alphabet(old, new)
    old_stepper = _Stepper(old)
    new_stepper = _Stepper(new)
    # Every normalized path starts with "/".
    seed = (
        "/",
        old_stepper.step(_initial_state(old), "/"),
        new_stepper.step(_initial_state(new), "/"),
    )
    queue: deque[tuple[str, _State, _State]] = deque([seed])
    seen = {(seed[1], seed[2])}
    explored = 0
    while queue:
        path, old_state, new_state = queue.popleft()
        explored += 1
        if path == _ROBOTS_TXT_PATH:
            old_allowed = new_allowed = True
        else:
            old_allowed = _verdict(old, old_state)
            new_allowed = _verdict(new, new_state)
        if old_allowed != new_allowed:
            return PolicyDiff("different", path, old_allowed, new_allowed, explored)
        for char in alphabet:
            next_states = (
                old_stepper.step(old_state, char),
                new_stepper.step(new_state, char),
            )
            if next_states not in seen:
                seen.add(next_states)
                queue.append((path + char, next_states[0], next_states[1]))
        if explored >= max_states and queue:
            return PolicyDiff("unproven", None, None, None, explored)
    return PolicyDiff("equivalent", None, None, None, explored)


def enumerate_first_difference(
    old: Protego,
    new: Protego,
    user_agent: str,
    *,
    alphabet: str,
    max_length: int,
) -> tuple[str, bool, bool] | None:
    """Return the shortest path over *alphabet*, of at most *max_length*
    characters, that one version allows and the other disallows, as
    ``(path, old_allowed, new_allowed)``, or None if there is none.

    Independent of the proof engine above: it asks ``can_fetch()``
    directly, so small rule sets can cross-validate
    :meth:`protego.Protego.compare_policy` with it.
    """
    queue: deque[str] = deque(["/"])
    while queue:
        path = queue.popleft()
        url = _fetch_input(path)
        old_allowed = old.can_fetch(url, user_agent)
        new_allowed = new.can_fetch(url, user_agent)
        if old_allowed != new_allowed:
            return path, old_allowed, new_allowed
        if len(path) < max_length:
            queue.extend(path + char for char in alphabet)
    return None


def _fetch_input(path: str) -> str:
    """Return a URL whose normalized path is exactly *path*.

    Every string that starts with "/" normalizes to itself, except
    strings starting with "//", which urlsplit reads as an authority;
    an extra "//" prefix in the input produces those.
    """
    return "//" + path if path.startswith("//") else path
