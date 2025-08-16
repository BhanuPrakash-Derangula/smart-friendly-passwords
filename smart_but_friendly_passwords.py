"""
Smart But Friendly Passwords — Product-Aware Validator

This module implements `is_valid_password(password: str) -> bool` guided by the
product team’s principles. Because the guidance is intentionally flexible,
we translate it into a clear set of heuristics with comments that explain WHY
each rule exists and HOW it reflects the product intent.

PRODUCT INTENT → PRACTICAL INTERPRETATION
-----------------------------------------
1) "Reasonably secure (not trivially guessable)"
   - Minimum length (friendly but not tiny): 10+ preferred, 8–9 allowed with stronger mix.
   - Penalize obvious sequences (abcd, 1234, qwerty), repeated chunks, one-key spam.
   - Block a small set of notorious passwords ("password", "qwerty", etc.).

2) "Show signs of intentionality (not random key smashing)"
   - Require at least one “intentional signal”, such as:
     • Passphrase-like structure: 2+ real-looking word tokens separated by delimiters.
     • CamelCase with 2+ capitalized word segments (e.g., BlueParrotRodeo).
     • Word(s) + non-trivial number/date-ish info (e.g., RaviVizag_27Aug).
   - Penalize long consonant-only runs that look like “key mashing”.

3) "Avoid visually confusing or ambiguous patterns"
   - Reject if most characters are look-alikes (e.g., O/0, l/1/I, S/5, Z/2, B/8).
   - Light penalty if ambiguity is noticeable but not extreme.

4) "Balance between repetition and variation"
   - Penalize too much repetition (same char ≥ 4 in a row or short chunk repeated ≥ 3).
   - Allow *some* repetition (twice is fine); deliberate repetition can be human.

5) "Human structure that brute force might not favor"
   - Reward human patterns like: multiple words, CamelCase, meaningful separators,
     mixed types (letters/digits/symbols) without being rigid.

SCORING MODEL (transparent and tweakable)
-----------------------------------------
We compute a score and check "hard reject" conditions. A password is valid if:
  • No hard-reject triggers
  • Has at least one Intentional Signal
  • Score >= 3

Score components:
  + Length points:    8–9: +1, 10–11: +2, 12–15: +3, 16+: +4
  + Variety points:   presence of lower/upper/digit/symbol; sum-1 (cap at +3)
  + Intentionality:   passphrase-like +2, CamelCase +2, word+year/date-ish +1,
                      meaningful separators +1
  - Penalties:        common/banned -4, straight sequences -3,
                      keyboard walks -3, repeated chunk -2, long same-char run -2,
                      consonant-smash -2, ambiguous chars heavy: -1 or -3

Hard rejects:
  • length < 8
  • contains notorious password terms (e.g., "password", "qwerty", etc.)
  • very strong keyboard/alpha/numeric sequence (len >= 5)
  • ambiguous/visually confusing chars ≥ 60% of all chars

NOTE:
- The aim is product realism, not academic entropy proofs.
- Heuristics are intentionally conservative and commented for easy review.
"""

from __future__ import annotations
import re
import string
from typing import Dict, Tuple

# ---------------------------
# Public API
# ---------------------------

def is_valid_password(password: str) -> bool:
    """
    Return True if `password` is accepted by the "smart but friendly" policy; else False.
    """
    ok, _ = _validate_details(password)
    return ok


# ---------------------------
# Internal: detailed validator
# ---------------------------

def _validate_details(pw: str) -> Tuple[bool, Dict[str, int | bool | str]]:
    pw = pw.strip()
    info: Dict[str, int | bool | str] = {}

    # Basic signals
    length = len(pw)
    info["length"] = length

    # Hard reject: too short to be "reasonably secure"
    if length < 8:
        info["reason"] = "too_short"
        return False, info

    # Character classes
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in string.punctuation or c.isspace() for c in pw)
    info.update(dict(has_lower=has_lower, has_upper=has_upper,
                     has_digit=has_digit, has_symbol=has_symbol))

    # Notorious/banned terms that are trivially guessable.
    banned_terms = {
        "password", "qwerty", "letmein", "welcome", "iloveyou",
        "dragon", "monkey", "admin", "login", "abc123"
    }
    low_pw = pw.lower()
    if any(term in low_pw for term in banned_terms):
        info["reason"] = "banned_term"
        return False, info  # Hard reject

    # Visual ambiguity measurement (O/0, l/1/I/|, S/5, Z/2, B/8, G/6, Q/0, etc.)
    ambiguous_set = set("0Oo1lI|5S2Z8B6G9gQq")
    amb_count = sum(ch in ambiguous_set for ch in pw)
    amb_ratio = amb_count / max(1, length)
    info["ambiguous_ratio"] = round(amb_ratio, 3)
    if amb_ratio >= 0.60:
        info["reason"] = "too_ambiguous"
        return False, info  # Hard reject

    # Sequences (alphabetic/numeric +/-1 steps) and keyboard walks (qwerty/asdf/zxcv).
    seq_len = _longest_linear_sequence(pw)
    kb_len = _longest_keyboard_walk(pw)
    info["longest_linear_sequence"] = seq_len
    info["longest_keyboard_walk"] = kb_len
    if max(seq_len, kb_len) >= 5:
        info["reason"] = "too_sequential"
        return False, info  # Hard reject

    # Repetition checks
    max_run = _max_same_char_run(pw)
    repeated_chunk = _is_repeated_short_chunk(pw)
    info["max_same_char_run"] = max_run
    info["repeated_short_chunk"] = repeated_chunk

    # "Key smashing" detector: long consonant run without vowels
    smashy = _looks_like_consonant_smash(pw)
    info["consonant_smash"] = smashy

    # Intentional signals:
    passphrase_like = _looks_like_passphrase(pw)
    camel_segments = _camel_case_segments(pw) >= 2
    word_plus_dateish = _has_word_plus_dateish(pw)
    meaningful_separators = any(sep in pw for sep in "-_ .")
    has_intent_signal = passphrase_like or camel_segments or word_plus_dateish
    info.update(dict(passphrase_like=passphrase_like,
                     camel_case=camel_segments,
                     word_plus_dateish=word_plus_dateish,
                     meaningful_separators=meaningful_separators))

    # ---------------------------
    # Score assembly
    # ---------------------------
    score = 0

    # Length points (friendly but nudges users longer)
    if 8 <= length <= 9:
        score += 1
    elif 10 <= length <= 11:
        score += 2
    elif 12 <= length <= 15:
        score += 3
    else:  # 16+
        score += 4

    # Variety points (we prefer variety, but don't over-police)
    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += min(3, max(0, variety_count - 1))  # 0..3

    # Intentionality rewards
    if passphrase_like:
        score += 2
    if camel_segments:
        score += 2
    if word_plus_dateish:
        score += 1
    if meaningful_separators and (passphrase_like or camel_segments):
        score += 1

    # Penalties
    if seq_len >= 4:
        score -= 3
    if kb_len >= 4:
        score -= 3
    if repeated_chunk:
        score -= 2
    if max_run >= 4:
        score -= 2
    if smashy:
        score -= 2
    if 0.30 <= amb_ratio < 0.60:
        score -= 1

    info["score"] = score
    info["has_intent_signal"] = has_intent_signal

    # Acceptance gate
    if not has_intent_signal:
        info["reason"] = "no_intent_signal"
        return False, info
    if score >= 3:
        info["reason"] = "accepted"
        return True, info
    else:
        info["reason"] = "low_score"
        return False, info


# ---------------------------
# Heuristic helpers
# ---------------------------

def _longest_linear_sequence(pw: str) -> int:
    """
    Detects longest run where consecutive chars step by +1 or -1 in ASCII
    (e.g., 'abcd', '4321', 'WXYZ', '9876'). Case-insensitive for letters.
    """
    if not pw:
        return 0
    # Normalize letters to a single case to catch 'aBcD' as a sequence.
    norm = []
    for ch in pw:
        if ch.isalpha():
            norm.append(ch.lower())
        else:
            norm.append(ch)
    s = "".join(norm)

    def step(a: str, b: str) -> int | None:
        if len(a) != 1 or len(b) != 1:
            return None
        return ord(b) - ord(a)

    best = 1
    cur = 1
    last_step = None
    for i in range(1, len(s)):
        st = step(s[i-1], s[i])
        if st in (1, -1):  # linear step
            if last_step == st:
                cur += 1
            else:
                cur = 2
            last_step = st
            best = max(best, cur)
        else:
            cur = 1
            last_step = None
    return best


def _longest_keyboard_walk(pw: str) -> int:
    """
    Detects qwerty-style walks across the main rows.
    We check for substrings length >= 4 on rows or their reverse.
    """
    rows = [
        "`1234567890-=",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    lowers = pw.lower()
    best = 1
    for row in rows:
        best = max(best, _longest_substring_on_line(lowers, row))
        best = max(best, _longest_substring_on_line(lowers, row[::-1]))
    return best


def _longest_substring_on_line(text: str, line: str) -> int:
    """
    Longest contiguous substring of `text` that appears as a contiguous slice of `line`.
    """
    best = 1
    n = len(text)
    for i in range(n):
        for j in range(i + best + 1, min(n, i + 12) + 1):  # cap for perf; we only care up to ~12
            if text[i:j] in line:
                best = max(best, j - i)
    return best


def _max_same_char_run(pw: str) -> int:
    """
    Maximum run of the same character (e.g., 'aaaa' -> 4).
    """
    best = 1
    current = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def _is_repeated_short_chunk(pw: str) -> bool:
    """
    Returns True if password looks like X repeated >= 3 times where len(X) in [1..3].
    e.g., 'aaabbb' (chunks len 1) or 'abcabcabc' (len 3).
    """
    n = len(pw)
    for k in (1, 2, 3):
        if n % k == 0:
            chunk = pw[:k]
            repeats = n // k
            if repeats >= 3 and chunk * repeats == pw:
                return True
    # Also catch len-2 chunks repeated 3+ times inside (e.g., 'xyxyxyZ')
    for k in (1, 2, 3):
        chunk = pw[:k]
        if pw.count(chunk) >= 3 and len(chunk) * 3 <= n:
            # Occurs at least 3 times; heuristic only (not strict tiling)
            return True
    return False


def _looks_like_consonant_smash(pw: str) -> bool:
    """
    Heuristic for "key smashing": long alphabetic runs with very few vowels.
    If we find an alpha-only substring of length >= 7 where vowel ratio < 0.2.
    """
    vowels = set("aeiouAEIOU")
    for token in re.findall(r"[A-Za-z]{7,}", pw):
        v = sum(ch in vowels for ch in token)
        if v / len(token) < 0.2:
            return True
    return False


def _looks_like_passphrase(pw: str) -> bool:
    """
    True if it looks like multiple word tokens separated by delimiters.
    We consider 2+ alphabetic tokens of length >= 3 as passphrase-like.
    """
    tokens = [t for t in re.split(r"[^A-Za-z]+", pw) if len(t) >= 3]
    return len(tokens) >= 2


def _camel_case_segments(pw: str) -> int:
    """
    Count segments like 'Blue' in CamelCase ('BlueParrotRodeo' = 3 segments).
    """
    segments = re.findall(r"[A-Z][a-z]{2,}", pw)
    return len(segments)


def _has_word_plus_dateish(pw: str) -> bool:
    """
    Checks for combos like words + year (19xx/20xx), or common date-like bits (e.g., 27Aug).
    We avoid rewarding trivial '1234'.
    """
    low = pw.lower()
    # Year: 1900..2099
    has_year = re.search(r"\b(19|20)\d{2}\b", low) is not None

    # Month abbreviations/names (english) common in passwords
    months = ("jan", "feb", "mar", "apr", "may", "jun",
              "jul", "aug", "sep", "oct", "nov", "dec")
    has_month = any(m in low for m in months)

    # Check presence of a legitimate word-ish token
    word_tokens = [t for t in re.split(r"[^A-Za-z]+", pw) if len(t) >= 3]
    has_word = len(word_tokens) >= 1

    # We also exclude trivial sequences around the numeric part
    # by ensuring no long linear sequence is present.
    not_trivial_seq = _longest_linear_sequence(pw) < 4

    return has_word and (has_year or has_month) and not_trivial_seq


# ---------------------------
# Developer Demo (manual tests)
# ---------------------------

if __name__ == "__main__":
    demo = [
        "BlueParrot!42",            # CamelCase + symbol + digits → likely True
        "happy-biryani-2025!",     # Passphrase-ish + year + symbol → True
        "Ravi@Vizag_27Aug",        # Word+place+date-ish → True
        "qwerty12345",             # Keyboard walk + sequence → False
        "ASDFGHJKL",               # Straight row in caps → False
        "xjkdf&$2L",               # Short and smashy; lacks intent → False
        "BookBook!!2024",          # Repeated word OK with variation → likely True
        "1111Cool!!",              # Long digit run → likely False
        "O0Il1|S5Z2B8",            # Highly ambiguous → False
        "GreenTea--Morning@16",    # Structured → True
        "abcabcabc",               # Repeated chunk → False
        "Abcdefg123!",             # Linear alpha seq → False
        "BlueSky",                 # Too short → False
    ]

    for p in demo:
        ok, details = _validate_details(p)
        print(f"{p!r:>24} -> {ok} (score={details.get('score')}, reason={details.get('reason')})")
