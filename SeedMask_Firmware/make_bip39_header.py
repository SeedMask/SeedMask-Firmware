# Generates bip39_en.h (English BIP39 wordlist) for Arduino PROGMEM.
# Usage:
#   python3 make_bip39_header.py

WORDS = [
# The script will download the official list if you paste it here,
# but to keep this zero-drama, we embed the official BIP39 English list below as a URL fetch alternative.
]

import sys, textwrap, urllib.request

URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

def main():
    print("Downloading BIP39 wordlist...")
    data = urllib.request.urlopen(URL, timeout=30).read().decode("utf-8")
    words = [w.strip() for w in data.splitlines() if w.strip()]
    if len(words) != 2048:
      raise SystemExit(f"Expected 2048 words, got {len(words)}")

    out = []
    out.append("#pragma once")
    out.append("#include <Arduino.h>")
    out.append("")
    out.append("static const char * const BIP39_WORDS[2048] PROGMEM = {")
    for w in words:
      out.append(f'  PSTR("{w}"),')
    out.append("};")
    out.append("")

    with open("bip39_en.h", "w", encoding="utf-8") as f:
      f.write("\n".join(out))

    print("Wrote bip39_en.h (2048 words).")

if __name__ == "__main__":
    main()
