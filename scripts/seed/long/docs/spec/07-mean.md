# 7. mean

Module: `textkit/numbers.py`. Tests: `tests/test_numbers.py`.

    mean(values)

Return the sum of the values divided by their number, as a float. An empty sequence raises ValueError.

Examples:

    mean([1, 2, 3, 4]) == 2.5
    mean([5]) == 5.0
    mean([]) raises ValueError
