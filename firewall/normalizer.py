
import base64
import codecs
import re
import unicodedata


# Characters sometimes inserted to hide text from simple filters.
ZERO_WIDTH_CHARS = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff"),
    None
)

# Common leetspeak substitutions.
LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s"
})

# Candidate Base64 strings.
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])"
)

# Detect explicit requests to decode ROT13.
ROT13_MARKER = re.compile(
    r"\brot\s*[- ]?13\b",
    re.IGNORECASE
)


def normalize_text(text: str) -> str:
    """
    Normalize text without changing its meaning intentionally.

    Operations:
    1. Unicode NFKC normalization
    2. Remove zero-width characters
    3. Convert to lowercase
    4. Remove separators between dotted/obfuscated letters
    5. Normalize whitespace
    """

    if not isinstance(text, str):
        raise TypeError("Prompt must be a string.")

    # Normalize Unicode representations.
    text = unicodedata.normalize("NFKC", text)

    # Remove invisible characters.
    text = text.translate(ZERO_WIDTH_CHARS)

    # Lowercase.
    text = text.lower()

    # Handle dotted or punctuation-separated words:
    # i.g.n.o.r.e -> ignore
    text = re.sub(
        r"(?<!\w)(?:[a-z][.\-_*]){2,}[a-z](?!\w)",
        lambda match: re.sub(r"[.\-_*]", "", match.group()),
        text
    )

    # Normalize repeated whitespace.
    text = re.sub(r"\s+", " ", text).strip()

    return text


def create_variants(text: str) -> list[dict]:
    """
    Generate alternative representations for inspection.

    These variants are additional inspection inputs.
    They do not replace the original user prompt.
    """

    variants = []

    def add_variant(source: str, value: str):
        value = normalize_text(value)

        if not value:
            return

        # Avoid duplicate variants.
        if any(item["text"] == value for item in variants):
            return

        variants.append({
            "source": source,
            "text": value
        })

    normalized = normalize_text(text)

    # Standard normalized version.
    add_variant("normalized", normalized)

    # Leetspeak decoding.
    leet_decoded = normalized.translate(LEET_TRANSLATION)

    if leet_decoded != normalized:
        add_variant("leetspeak", leet_decoded)

    # Base64 decoding.
    for match in BASE64_PATTERN.finditer(text):

        encoded = match.group()

        try:
            padding = "=" * (-len(encoded) % 4)

            decoded_bytes = base64.b64decode(
                encoded + padding,
                validate=True
            )

            decoded_text = decoded_bytes.decode("utf-8")

            # Avoid treating binary or control-character output
            # as ordinary readable text.
            if (
                decoded_text.isprintable()
                and decoded_text.strip()
            ):
                add_variant("base64", decoded_text)

        except (ValueError, UnicodeDecodeError):
            continue

    # ROT13 decoding is attempted only when the prompt
    # explicitly mentions ROT13.
    if ROT13_MARKER.search(normalized):

        try:
            decoded_rot13 = codecs.decode(text, "rot_13")

            add_variant("rot13", decoded_rot13)

        except (UnicodeError, ValueError):
            pass

    return variants


def normalize_prompt(text: str) -> dict:
    """
    Main public function used by the firewall.

    Returns the original prompt, normalized text,
    and alternative variants for inspection.
    """

    if not isinstance(text, str):
        raise TypeError("Prompt must be a string.")

    normalized = normalize_text(text)

    variants = create_variants(text)

    return {
        "original": text,
        "normalized": normalized,
        "variants": variants
    }
