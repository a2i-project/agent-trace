# 6. clamp

Module: `textkit/numbers.py`. Tests: `tests/test_numbers.py`.

    clamp(x, lo, hi)

Return lo when x is below lo, hi when x is above hi, and x otherwise. lo greater than hi raises ValueError.

Examples:

    clamp(5, 0, 3) == 3
    clamp(-1, 0, 3) == 0
    clamp(2, 0, 3) == 2
    clamp(1, 3, 0) raises ValueError
