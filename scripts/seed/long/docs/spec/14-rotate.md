# 14. rotate

Module: `textkit/lists.py`. Tests: `tests/test_lists.py`.

    rotate(items, k)

Return a new list with the items rotated left by k places. k may be negative (rotate right) or larger than the number of items. No items give an empty list.

Examples:

    rotate([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    rotate([1, 2, 3], -1) == [3, 1, 2]
    rotate([1, 2, 3], 7) == [2, 3, 1]
    rotate([], 5) == []
