import json
from pathlib import Path

HERE = Path(__file__).parent


def fixture_json(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))
