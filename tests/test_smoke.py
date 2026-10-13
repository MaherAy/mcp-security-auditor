"""Smoke test: the package is importable (phase 0)."""

import auditor


def test_package_importable():
    assert auditor.__doc__
