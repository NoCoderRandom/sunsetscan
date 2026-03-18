"""
NetWatch EOL (End-of-Life) Module.

This package contains End-of-Life checking functionality:
- checker: EOL API queries and version comparison logic
- cache: Local JSON cache management with TTL
- product_map: Software name to endoflife.date slug mappings
"""

from eol.checker import EOLChecker
from eol.cache import CacheManager
from eol.product_map import get_product_slug

__all__ = [
    "EOLChecker",
    "CacheManager",
    "get_product_slug",
]
