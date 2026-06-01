#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.gitops_config import validate_all


def main() -> None:
    validate_all()
    print("gitops config validation passed")


if __name__ == "__main__":
    main()
