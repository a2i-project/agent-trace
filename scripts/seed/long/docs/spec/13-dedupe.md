# 13. dedupe

Module: `textkit/lists.py`. Tests: `tests/test_lists.py`.

    dedupe(items)

Return a list of the items with every repeat removed, each kept at its first occurrence. Items are hashable.

Examples:

    dedupe([3, 1, 3, 2, 1]) == [3, 1, 2]
    dedupe([]) == []
    dedupe("abca") == ["a", "b", "c"]
