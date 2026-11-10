from __future__ import annotations

from typing import TYPE_CHECKING

from ._urlpattern import _EXACT, _PREFIX, _WILDCARD, _rule_matches

if TYPE_CHECKING:
    from ._urlpattern import _FlatRule


class _TrieNode:
    """One node of the rule index trie.

    ``prefix_rank`` marks a plain prefix rule ending on the node and
    ``wildcard_ranks`` collects wildcard rules whose first part ends there.
    Both fields stay ``None`` until a rule actually needs them, so a node on a
    shared path costs only the dict of its children.
    """

    __slots__ = ("children", "prefix_rank", "wildcard_ranks")

    def __init__(self) -> None:
        self.children: dict[str, _TrieNode] | None = None
        self.prefix_rank: int | None = None
        self.wildcard_ranks: list[int] | None = None


class _RuleIndex:
    """Index the flattened rules of one user-agent group.

    Plain prefix rules and the first parts of wildcard rules share a character
    trie; exact rules live in a hash table. A single walk of the URL therefore
    touches only the prefix rules that are prefixes of it, the wildcard rules
    whose first part starts it, and at most one exact rule, instead of
    scanning every rule in the group.

    Space is linear in the total pattern text: each trie edge stores one
    character, and no path or candidate URL is ever materialized.
    """

    __slots__ = ("_rules", "_root", "_exact")

    def __init__(self, rules: list[_FlatRule]) -> None:
        self._rules = rules
        self._root = _TrieNode()
        self._exact: dict[str, int] = {}
        for rank, (kind, data, _is_disallow) in enumerate(rules):
            if kind == _PREFIX:
                self._insert_prefix(data, rank)
            elif kind == _EXACT:
                self._insert_exact(data, rank)
            else:
                self._insert_wildcard(data[0], rank)

    def _node_for(self, text: str) -> _TrieNode:
        """Return the node reached by *text*, creating the missing path."""
        node = self._root
        for char in text:
            children = node.children
            if children is None:
                children = {}
                node.children = children
            child = children.get(char)
            if child is None:
                child = _TrieNode()
                children[char] = child
            node = child
        return node

    def _insert_prefix(self, pattern: str, rank: int) -> None:
        node = self._node_for(pattern)
        # Rules are handed over in the precedence order, so the first rule
        # stored for an equal pattern is the winning one.
        if node.prefix_rank is None:
            node.prefix_rank = rank

    def _insert_exact(self, pattern: str, rank: int) -> None:
        self._exact.setdefault(pattern, rank)

    def _insert_wildcard(self, first_part: str, rank: int) -> None:
        node = self._node_for(first_part)
        wildcard_ranks = node.wildcard_ranks
        if wildcard_ranks is None:
            node.wildcard_ranks = [rank]
        else:
            wildcard_ranks.append(rank)

    def _choose(self, best: int | None, candidate: int | None) -> int:
        if candidate is not None and (best is None or candidate < best):
            return candidate
        return best

    def match(self, url: str) -> bool:
        """Return whether *url* may be fetched according to the indexed rules."""
        best = self._exact.get(url)
        node = self._root
        url_length = len(url)
        rules = self._rules
        for index in range(url_length + 1):
            prefix_rank = node.prefix_rank
            if prefix_rank is not None:
                best = self._choose(best, prefix_rank)
            wildcard_ranks = node.wildcard_ranks
            if wildcard_ranks is not None:
                for rank in wildcard_ranks:
                    kind, data, _is_disallow = rules[rank]
                    if _rule_matches(kind, data, url):
                        best = self._choose(best, rank)
            if index == url_length:
                break
            children = node.children
            if children is None:
                break
            node = children.get(url[index])
            if node is None:
                break
        if best is None:
            return True
        return not rules[best][2]

    def match_with_check_count(self, url: str) -> tuple[bool, int]:
        """As :meth:`match`, but also report how many rules were evaluated.

        The count is the number of rule comparisons a query actually performs:
        one per candidate rule the index hands to the precedence arbitration.
        Prefix and exact candidates are already proven by the trie walk and
        the exact hash lookup; every wildcard candidate still has its full
        ``find``-based comparison run and counts as one check.
        """
        checks = 0
        best = self._exact.get(url)
        if best is not None:
            checks += 1
        node = self._root
        url_length = len(url)
        rules = self._rules
        for index in range(url_length + 1):
            prefix_rank = node.prefix_rank
            if prefix_rank is not None:
                checks += 1
                best = self._choose(best, prefix_rank)
            wildcard_ranks = node.wildcard_ranks
            if wildcard_ranks is not None:
                for rank in wildcard_ranks:
                    checks += 1
                    kind, data, _is_disallow = rules[rank]
                    if _rule_matches(kind, data, url):
                        best = self._choose(best, rank)
            if index == url_length:
                break
            children = node.children
            if children is None:
                break
            node = children.get(url[index])
            if node is None:
                break
        if best is None:
            return True, checks
        return not rules[best][2], checks
