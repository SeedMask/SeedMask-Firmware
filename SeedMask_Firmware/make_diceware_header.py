#!/usr/bin/env python3
# Generates diceware_words.h from the official Reinhold Diceware list (7776 words).
# Usage: python3 make_diceware_header.py

import urllib.request

URL = "https://theworld.com/~reinhold/diceware.wordlist.asc"
EXPECTED = 7776


def escape_c(s: str) -> str:
    out = []
    for c in s:
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        else:
            out.append(c)
    return "".join(out)


def main():
    print("Downloading Diceware wordlist...")
    data = urllib.request.urlopen(URL, timeout=30).read().decode("utf-8", errors="replace")
    words = []
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        # Format: "11111\ta" or "11112\ta&p" (tab-separated)
        if "\t" in line:
            num, word = line.split("\t", 1)
            if len(num) == 5 and num.isdigit():
                words.append(escape_c(word))
    if len(words) != EXPECTED:
        raise SystemExit(f"Expected {EXPECTED} words, got {len(words)}")

    out = [
        "#pragma once",
        "#include <Arduino.h>",
        "",
        f"#define DICEWARE_WORD_COUNT {EXPECTED}",
        "",
        "static const char * const DICEWARE_WORDS[DICEWARE_WORD_COUNT] PROGMEM = {",
    ]
    for w in words:
        out.append(f'  PSTR("{w}"),')
    out.append("};")
    out.append("")

    with open("diceware_words.h", "w", encoding="utf-8") as f:
        f.write("\n".join(out))

    print(f"Wrote diceware_words.h ({EXPECTED} words).")


if __name__ == "__main__":
    main()
