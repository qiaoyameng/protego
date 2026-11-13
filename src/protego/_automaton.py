from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, FrozenSet


class BudgetExceeded(Exception):
    """Raised when automaton construction or exploration hits its budget."""


class _NFABuilder:
    """Incremental builder of a small epsilon NFA.

    Literal edges and wildcard edges never meet on the same node. Each
    ``*`` becomes its own wildcard node with a self-loop (greedy expansion)
    and an epsilon edge (the empty match); the following literal starts from
    a fresh node. Nondeterminism between the two edges reproduces the
    greedy-then-backtrack behavior of the library's ``str.find`` matcher.
    """

    def __init__(self) -> None:
        self._literal: list[dict[str, list[int]]] = [{}]
        self._wildcard: list[set[int]] = [set()]
        self._epsilon: list[set[int]] = [set()]

    def new_node(self) -> int:
        self._literal.append({})
        self._wildcard.append(set())
        self._epsilon.append(set())
        return len(self._literal) - 1

    def add_literal(self, start: int, text: str) -> int:
        node = start
        for char in text:
            nxt = self.new_node()
            self._literal[node].setdefault(char, []).append(nxt)
            node = nxt
        return node

    def add_star(self, start: int) -> int:
        node = self.new_node()
        self._epsilon[start].add(node)
        nxt = self.new_node()
        self._wildcard[node].add(node)
        self._epsilon[node].add(nxt)
        return nxt

    def add_epsilon(self, start: int, target: int) -> None:
        self._epsilon[start].add(target)

    def build(self, accept: int) -> _NFA:
        return _NFA(
            literal=tuple(
                dict((char, tuple(targets)) for char, targets in edges.items())
                for edges in self._literal
            ),
            wildcard=tuple(frozenset(targets) for targets in self._wildcard),
            epsilon=tuple(frozenset(targets) for targets in self._epsilon),
            accept=accept,
        )


@dataclass(frozen=True)
class _NFA:
    literal: tuple[dict[str, tuple[int, ...]], ...]
    wildcard: tuple[frozenset[int], ...]
    epsilon: tuple[frozenset[int], ...]
    accept: int

    def closure(self, starts: Iterable[int]) -> FrozenSet[int]:
        seen = set(starts)
        stack = list(seen)
        while stack:
            node = stack.pop()
            for target in self.epsilon[node]:
                if target not in seen:
                    seen.add(target)
                    stack.append(target)
        return frozenset(seen)


@dataclass(frozen=True)
class DFA:
    """A complete deterministic automaton over a shared alphabet.

    ``representatives`` lists one concrete character per alphabet class;
    every literal used to build the automaton owns its own singleton class,
    so the last representative stands for every other character.
    """

    representatives: tuple[str, ...]
    transitions: tuple[tuple[int, ...], ...]
    accepting: frozenset[int]


def determinize(
    nfa: _NFA, representatives: tuple[str, ...], max_states: int
) -> DFA:
    """Turn an NFA into a complete DFA through subset construction."""
    start_set = nfa.closure((0,))
    subsets: dict[FrozenSet[int], int] = {start_set: 0}
    queue: deque[FrozenSet[int]] = deque([start_set])
    transitions: list[tuple[int, ...]] = []

    while queue:
        current = queue.popleft()
        row: list[int] = []
        for representative in representatives:
            targets: list[int] = []
            for node in current:
                explicit = nfa.literal[node].get(representative)
                if explicit:
                    targets.extend(explicit)
                if not explicit:
                    # A wildcard position still matches the character when no
                    # literal edge does; literal edges take precedence.
                    targets.extend(nfa.wildcard[node])
            nxt = nfa.closure(targets)
            index = subsets.get(nxt)
            if index is None:
                index = len(subsets)
                if index > max_states:
                    raise BudgetExceeded(
                        f"DFA subset construction exceeded {max_states} states"
                    )
                subsets[nxt] = index
                queue.append(nxt)
            row.append(index)
        transitions.append(tuple(row))

    accepting = frozenset(
        index for subset, index in subsets.items() if nfa.accept in subset
    )
    return DFA(representatives, tuple(transitions), accepting)
