import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).parent.parent / "data"


@lru_cache(maxsize=None)
def load_data(name: str):
    path = _DATA_DIR / name
    with path.open(encoding="utf-8") as f:
        return json.load(f)
