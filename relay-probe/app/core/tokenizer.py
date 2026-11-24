import hashlib
import json
import os
import random
from functools import lru_cache

import tiktoken

from app.config import ROOT

os.environ.setdefault("TIKTOKEN_CACHE_DIR", str(ROOT / "app/data/tokenizer"))


@lru_cache(maxsize=1)
def encoding():
    return tiktoken.get_encoding("o200k_base")


def count(text: str) -> int:
    return len(encoding().encode_ordinary(text))


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def input_count(body: dict) -> int:
    # Fixed wire skeleton + verbatim text. JSON escaping must not change the tokenizer
    # fingerprint of a newline, quote or code fragment in an otherwise identical request.
    keys = ("instructions", "input", "messages", "tools", "tool_choice", "text", "response_format")
    skeleton = {k: body[k] for k in keys if k in body}
    text_tokens = 0

    def extract(value):
        nonlocal text_tokens
        if isinstance(value, str):
            text_tokens += count(value)
            return ""
        if isinstance(value, list):
            return [extract(item) for item in value]
        if isinstance(value, dict):
            return {k: extract(v) if k in ("content", "text") else v for k,v in value.items()}
        return value

    for k in ("input", "instructions", "messages"):
        if k in skeleton:
            skeleton[k] = extract(skeleton[k])
    return count(compact(skeleton)) + text_tokens


WORDS = " amber ash atlas blue brass cedar clay cloud coral dawn delta dune fern field fog frost glass gold grain gray hill iron jade lake leaf lime map mint mist moon moss north oak orbit pearl pine plum pond rain reef ridge river rock rose ruby sand seed shore silk sky slate snow soft soil solar stone storm sun surf tide tree vale wave west wind wood zinc".split()


def padding(tokens: int, salt: str) -> str:
    if tokens <= 0:
        return ""
    rng = random.Random(int.from_bytes(hashlib.sha256(salt.encode()).digest(), "big"))
    text = salt + " " + " ".join(rng.choices(WORDS, k=tokens))
    enc = encoding()
    value = enc.decode(enc.encode_ordinary(text)[:tokens])
    if count(value) != tokens:
        raise ValueError("垫料分词验证失败")
    return value
