# wordstats

Count the words in a text file.

## Usage

    python3 -m wordstats.cli FILE

Prints each word with its count, most frequent first.

## Library

`wordstats.count_words(text)` returns a dict of word counts, ignoring case and
punctuation.

## Tests

    python3 -m unittest discover
