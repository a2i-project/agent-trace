# 12. flatten

Module: `textkit/lists.py`. Tests: `tests/test_lists.py`.

    flatten(nested)

Return one list with the items of each list in nested, in order. Only one level is flattened.

Examples:

    flatten([[1, 2], [3], []]) == [1, 2, 3]
    flatten([]) == []
    flatten([[1, [2]]]) == [1, [2]]
