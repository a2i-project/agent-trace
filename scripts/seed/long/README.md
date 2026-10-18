# textkit

Small text, number, list and encoding helpers, standard library only.

## Layout

    textkit/strings.py   slugify, truncate, wrap_words, is_palindrome, count_vowels
    textkit/numbers.py   clamp, mean, median, parse_int, roman
    textkit/lists.py     chunk, flatten, dedupe, rotate, interleave
    textkit/codec.py     caesar, rle_encode, rle_decode, hex_bytes, checksum
    textkit/cli.py       python3 -m textkit.cli NAME ARG...

Each function is specified in `docs/spec/`; `PLAN.md` gives the order.

## Commands

    make check            all tests and the lint
    make check-MODULE     one module's tests and lint, e.g. make check-strings
    make dist             build dist/textkit.pyz
    make clean            remove dist/
