# 11. chunk

Module: `textkit/lists.py`. Tests: `tests/test_lists.py`.

    chunk(items, size)

Return a list of lists holding the items in order, size per list; the last list may be shorter. No items give an empty list. A size below 1 raises ValueError.

Examples:

    chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    chunk([], 3) == []
    chunk([1], 0) raises ValueError
