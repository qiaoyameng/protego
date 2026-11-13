from __future__ import annotations

import re
from typing import Any

# The kinds of rule that a pattern boils down to: a prefix of the URL, the
# whole URL, or a sequence of parts to find in order.
_PREFIX = 0
_EXACT = 1
_WILDCARD = 2

# A rule as the match loop reads it: the kind of its pattern, the data that
# kind of comparison needs, and whether the rule disallows.
_FlatRule = tuple[int, Any, bool]


class _URLPattern:
    """Internal class which represents a URL pattern."""

    def __init__(self, pattern: str):
        self._pattern: str = pattern
        self.priority: int = len(pattern)

        if "*" in pattern:
            self.kind: int = _WILDCARD
            parts, anchored = self._prepare_wildcard_parts(pattern)
            first, last = parts[0], parts[-1]
            self.data: Any = (
                first,
                len(first),
                [(part, len(part)) for part in parts[1:-1]],
                last,
                len(last),
                anchored,
            )
        elif pattern.endswith("$"):
            self.kind = _EXACT
            self.data = pattern[:-1]
        else:
            self.kind = _PREFIX
            self.data = pattern

    @staticmethod
    def _prepare_wildcard_parts(pattern: str) -> tuple[list[str], bool]:
        ends_with_dollar = pattern.endswith("$")
        if ends_with_dollar:
            pattern = pattern[:-1]
        pattern = re.sub(r"\*+", "*", pattern)
        return pattern.split("*"), ends_with_dollar


def _matches(kind: int, data: Any, url: str) -> bool:
    """Return whether a single flattened rule matches *url*."""
    if kind == _PREFIX:
        return url.startswith(data)
    if kind == _EXACT:
        return url == data
    first, first_length, middle, last, last_length, anchored = data
    if not url.startswith(first):
        return False
    pos = first_length
    for part, part_length in middle:
        index = url.find(part, pos)
        if index == -1:
            return False
        pos = index + part_length
    if anchored:
        end = len(url) - last_length
        return end >= pos and url[end:] == last
    return not last or url.find(last, pos) != -1


def _match_rule(rules: list[_FlatRule], url: str) -> int:
    """Return the index of the first rule of *rules* matching *url*, or -1."""
    for index, (kind, data, _) in enumerate(rules):
        if _matches(kind, data, url):
            return index
    return -1


def _can_fetch(rules: list[_FlatRule], url: str) -> bool:
    """Return whether *url* may be fetched according to *rules*, the first
    matching rule deciding.
    """
    index = _match_rule(rules, url)
    return index == -1 or not rules[index][2]
