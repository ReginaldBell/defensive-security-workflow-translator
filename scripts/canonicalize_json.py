from __future__ import annotations

import json
import sys
from typing import Any


def _canonicalize(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON input: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(_canonicalize(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
