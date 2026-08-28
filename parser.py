#!/usr/bin/env python3
"""Compatibility wrapper for GitHub Actions (`python parser.py`)."""
from apex.geoip import init_geoip
from apex.sni_whitelist import init_sni_whitelist
from apex.main import main

if __name__ == "__main__":
    init_geoip()
    init_sni_whitelist()
    main()
