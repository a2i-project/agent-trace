# 15. interleave

Module: `textkit/lists.py`. Tests: `tests/test_lists.py`.

    interleave(a, b)

Return a list of a[0], b[0], a[1], b[1], and so on; when one list runs out, the rest of the other follows in order.

Examples:

    interleave([1, 2, 3], ["x"]) == [1, "x", 2, 3]
    interleave([], [1, 2]) == [1, 2]
    interleave([1], [2]) == [1, 2]
