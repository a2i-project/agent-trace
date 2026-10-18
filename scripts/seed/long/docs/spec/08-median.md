# 8. median

Module: `textkit/numbers.py`. Tests: `tests/test_numbers.py`.

    median(values)

Sort a copy of the values. With an odd number of values return the middle one; with an even number return the mean of the two middle ones as a float. The argument is not modified. An empty sequence raises ValueError.

Examples:

    median([3, 1, 2]) == 2
    median([4, 1, 3, 2]) == 2.5
    median([]) raises ValueError
