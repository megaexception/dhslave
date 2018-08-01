#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

from random import randint


def gen_opt82(opttype="Circuit-ID", value="opt82 text"):
    subtypes = {'Circuit-ID': 1}
    return subtypes.get(opttype).to_bytes(1, "big") + len(value).to_bytes(1, "big") + value.encode("ascii")


def gen_mac() -> bytes:
    return ((3*2**40^2**48-1)&randint(0, 2 ** 48)).to_bytes(6, 'big')
