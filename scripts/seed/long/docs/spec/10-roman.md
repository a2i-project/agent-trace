# 10. roman

Module: `textkit/numbers.py`. Tests: `tests/test_numbers.py`.

    roman(n)

Return the integer n, from 1 to 3999, in standard Roman numerals with subtractive pairs (IV, IX, XL, XC, CD, CM). Any other n raises ValueError.

Examples:

    roman(1987) == "MCMLXXXVII"
    roman(4) == "IV"
    roman(3999) == "MMMCMXCIX"
    roman(0) raises ValueError
