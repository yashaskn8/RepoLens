"""Shared versioned lexical normalization; no query-time vocabulary scans."""

import re
from collections import Counter

TOKENIZER_VERSION = "identifier-tokens/1"


def lexical_tokens(text: str) -> Counter:
    words = re.findall(r"\w+", text)
    result = Counter()
    for word in words:
        forms = {word.lower()}
        forms.update(part.lower() for part in re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", word).split("_"))
        for form in sorted(forms):
            if 1 < len(form) <= 128:
                result[form] += 1
    return result
