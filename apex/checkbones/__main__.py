"""Раннер checkbones: собирает пакеты checks_*.py и гоняет функции check_*.

Вывод построчный, итог — код возврата: 0 если все «костяшки» целы.
--quick пропускает тяжёлые модули (пометка SLOW = True), работая без сети и ядра.
"""
from __future__ import annotations

import importlib
import pkgutil
import sys
import traceback

from . import __path__ as _pkg_path


def _discover():
    mods = []
    for m in pkgutil.iter_modules(_pkg_path):
        if m.name.startswith("checks_"):
            mods.append(importlib.import_module(f".{m.name}", __package__))
    return sorted(mods, key=lambda m: m.__name__)


def main(argv: list) -> int:
    quick = "--quick" in argv
    failures = []
    passed = 0

    for mod in _discover():
        if quick and getattr(mod, "SLOW", False):
            print(f"⏭  {mod.__name__.split('.')[-1]}: пропущен (--quick)")
            continue
        checks = [n for n in dir(mod) if n.startswith("check_")]
        for name in sorted(checks):
            fn = getattr(mod, name)
            label = f"{mod.__name__.split('.')[-1]}.{name}"
            try:
                fn()
                passed += 1
                print(f"✅ {label}")
            except AssertionError as e:
                failures.append((label, f"FAIL: {e}"))
                print(f"❌ {label}: FAIL: {e}")
            except Exception as e:
                failures.append((label, f"ERROR: {type(e).__name__}: {e}"))
                print(f"💥 {label}: ERROR: {type(e).__name__}: {e}")

    print()
    if failures:
        print(f"🦴 Checkbones: {passed} целы, {len(failures)} СЛОМАНЫ")
        for label, msg in failures:
            print(f"   └ {label}: {msg}")
        return 1

    print(f"🦴 Checkbones: все {passed} костяшки целы")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
