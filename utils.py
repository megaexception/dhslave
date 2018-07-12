#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

def gen_opt82(opttype="Circuit-ID", value="opt82 text"):
    subtypes = {'Circuit-ID': 1}
    return subtypes.get(opttype).to_bytes(1, "big") + len(value).to_bytes(1, "big") + value.encode("ascii")
