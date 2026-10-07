import sys

from .core import count_words


def main(argv):
    """Print each word of the file named in argv[0] with its count, most
    frequent first, ties in alphabetical order. Return the exit status."""
    if len(argv) != 1:
        print("usage: wordstats FILE", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        counts = count_words(f.read())
    for word, n in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"{word} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
