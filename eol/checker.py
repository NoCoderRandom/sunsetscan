"""
NetWatch EOL Checker Module.

This module checks software End-of-Life status using locally cached data
from endoflife.date. No live API calls are made during scans — all data
must be pre-populated via --setup or --update-cache.

Uses the packaging library for semantic version comparison and determines
EOL status levels (CRITICAL, WARNING, OK, UNKNOWN).

Exports:
    EOLChecker: Main class for EOL checking
    EOLStatus: Dataclass for EOL status results
    EOLStatusLevel: Enum for status levels

Example:
    from eol.checker import EOLChecker
    checker = EOLChecker()
    
    status = checker.check_version("ubuntu", "20.04")
    print(f"Status: {status.level}, EOL Date: {status.eol_date}")
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from packaging import version as pkg_version

from config.settings import Settings, EOL_STATUS
from eol.cache import CacheManager
from eol.product_map import get_product_slug, NOT_TRACKED_PRODUCTS

logger = logging.getLogger(__name__)


class EOLStatusLevel(Enum):
    """EOL status levels."""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    OK = "OK"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "N/A"


@dataclass
class EOLStatus:
    """Result of an EOL check.
    
    Attributes:
        product: Product name checked
        version: Version that was checked
        level: EOL status level (CRITICAL/WARNING/OK/UNKNOWN)
        eol_date: End-of-Life date if known
        days_remaining: Days until (or since) EOL
        latest_version: Latest available version
        message: Human-readable status message
        details: Additional details from API
    """
    product: str
    version: str
    level: EOLStatusLevel
    eol_date: Optional[datetime] = None
    days_remaining: Optional[int] = None
    latest_version: str = ""
    message: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    @property
    def is_eol(self) -> bool:
        """Check if product has reached EOL."""
        return self.level == EOLStatusLevel.CRITICAL
    
    @property
    def color(self) -> str:
        """Get color code for this status level."""
        return EOL_STATUS.get(self.level.value, {}).get('color', 'dim')


class EOLChecker:
    """Checker for software End-of-Life status.

    This class reads locally cached EOL data to determine if a software
    version has reached EOL, is approaching EOL, or is still supported.
    No live API calls are made — data must be pre-populated via --setup.

    Attributes:
        cache: CacheManager instance for cached EOL data
        settings: Settings configuration object

    Example:
        checker = EOLChecker()

        # Check a specific version
        status = checker.check_version("ubuntu", "20.04")

        # Check with auto-detection from banner
        status = checker.check_banner("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")

        # Get all available cycles for a product
        cycles = checker.get_product_cycles("nodejs")
    """

    def __init__(
        self,
        cache: Optional[CacheManager] = None,
        settings: Optional[Settings] = None
    ):
        """Initialize the EOL checker.

        Args:
            cache: CacheManager instance (creates new if None)
            settings: Settings configuration object
        """
        self.settings = settings or Settings()
        self.cache = cache or CacheManager(settings=self.settings)
        logger.debug("EOLChecker initialized")
    
    def fetch_product_data(self, product: str) -> Optional[List[Dict]]:
        """Fetch EOL data for a product from local cache.

        Returns cached data or None if not cached. No live API calls are
        made — run --setup or --update-cache to populate the cache.

        Args:
            product: endoflife.date product slug

        Returns:
            List of version cycle data or None if unavailable
        """
        cached_data = self.cache.get(product)
        if cached_data:
            logger.debug(f"Using cached data for {product}")
            return cached_data
        logger.debug(f"No cached EOL data for {product} — run --setup to populate")
        return None
    
    def parse_eol_date(self, date_str: Any) -> Optional[datetime]:
        """Parse EOL date from various formats.
        
        Args:
            date_str: Date string or boolean from API
            
        Returns:
            Parsed datetime or None
        """
        if date_str is None or date_str == "":
            return None
        
        # Handle boolean (false means not EOL yet)
        if isinstance(date_str, bool):
            return None
        
        date_formats = [
            "%Y-%m-%d",
            "%Y-%m",
            "%Y",
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        logger.warning(f"Could not parse EOL date: {date_str}")
        return None
    
    def find_version_cycle(
        self, 
        cycles: List[Dict], 
        version: str
    ) -> Optional[Dict]:
        """Find the cycle data matching a specific version.
        
        Args:
            cycles: List of version cycle data from API
            version: Version to match
            
        Returns:
            Matching cycle data or None
        """
        if not version or not cycles:
            return None
        
        # Normalize version for comparison
        try:
            ver = pkg_version.parse(version)
        except Exception:
            ver = None
        
        for cycle in cycles:
            cycle_version = cycle.get('cycle', '')
            
            # Direct string match
            if cycle_version == version:
                return cycle
            
            # Try to match major version (e.g., "20.04" matches "20.04.x")
            if version.startswith(cycle_version + '.') or cycle_version.startswith(version + '.'):
                return cycle
            
            # Semantic version matching
            if ver:
                try:
                    cycle_ver = pkg_version.parse(cycle_version)
                    # Match if major.minor matches
                    if (ver.major == cycle_ver.major and 
                        ver.minor == cycle_ver.minor):
                        return cycle
                except Exception:
                    pass
        
        # Fallback: find closest matching major version
        try:
            ver_major = version.split('.')[0]
            for cycle in cycles:
                cycle_version = cycle.get('cycle', '')
                if cycle_version.split('.')[0] == ver_major:
                    return cycle
        except Exception:
            pass
        
        return None
    
    def check_version(
        self, 
        product: str, 
        version: str
    ) -> EOLStatus:
        """Check EOL status for a specific product version.
        
        Args:
            product: Product slug from endoflife.date
            version: Version string to check
            
        Returns:
            EOLStatus with detailed information
        """
        # Validate inputs
        if not product or not version or version == "unknown":
            return EOLStatus(
                product=product or "unknown",
                version=version or "unknown",
                level=EOLStatusLevel.NOT_APPLICABLE,
                message="Version not available for EOL check"
            )

        # Skip products we know are not tracked by endoflife.date
        if product in NOT_TRACKED_PRODUCTS:
            return EOLStatus(
                product=product,
                version=version,
                level=EOLStatusLevel.NOT_APPLICABLE,
                message=f"N/A — {product} not tracked by endoflife.date"
            )

        # Fetch product data
        cycles = self.fetch_product_data(product)
        if cycles is None:
            return EOLStatus(
                product=product,
                version=version,
                level=EOLStatusLevel.UNKNOWN,
                message=f"No EOL data available for {product}"
            )
        
        # Find matching cycle
        cycle = self.find_version_cycle(cycles, version)
        if cycle is None:
            return EOLStatus(
                product=product,
                version=version,
                level=EOLStatusLevel.UNKNOWN,
                message=f"Version {version} not found in EOL database",
                details={'available_cycles': [c.get('cycle') for c in cycles[:5]]}
            )
        
        # Determine EOL status
        return self._evaluate_eol_status(product, version, cycle, cycles)
    
    def _evaluate_eol_status(
        self,
        product: str,
        version: str,
        cycle: Dict,
        all_cycles: List[Dict]
    ) -> EOLStatus:
        """Evaluate EOL status from cycle data.
        
        Args:
            product: Product name
            version: Version string
            cycle: Matching cycle data
            all_cycles: All available cycles
            
        Returns:
            Evaluated EOLStatus
        """
        # Get EOL date
        eol_raw = cycle.get('eol')
        eol_date = self.parse_eol_date(eol_raw)
        
        # Get latest version info
        latest = cycle.get('latest', '')
        if not latest and all_cycles:
            # Try to find latest from all cycles
            latest = all_cycles[0].get('latest', '')
        
        # Calculate days remaining/since EOL
        days_remaining = None
        if eol_date:
            delta = eol_date - datetime.now()
            days_remaining = delta.days
        
        # Determine status level
        if eol_raw is False or eol_raw == "false":
            # Explicitly marked as not EOL
            level = EOLStatusLevel.OK
            message = f"{product} {version} is supported (no EOL date set)"
        elif eol_date is None:
            level = EOLStatusLevel.UNKNOWN
            message = f"EOL date unknown for {product} {version}"
        elif days_remaining is not None:
            if days_remaining < 0:
                level = EOLStatusLevel.CRITICAL
                message = f"{product} {version} reached EOL on {eol_date.strftime('%Y-%m-%d')}"
            elif days_remaining <= self.settings.warning_days_threshold:
                level = EOLStatusLevel.WARNING
                message = f"{product} {version} EOL approaching ({days_remaining} days)"
            else:
                level = EOLStatusLevel.OK
                message = f"{product} {version} is supported until {eol_date.strftime('%Y-%m-%d')}"
        else:
            level = EOLStatusLevel.UNKNOWN
            message = f"Could not determine EOL status for {product} {version}"
        
        return EOLStatus(
            product=product,
            version=version,
            level=level,
            eol_date=eol_date,
            days_remaining=days_remaining,
            latest_version=latest,
            message=message,
            details={
                'cycle': cycle.get('cycle'),
                'release_date': cycle.get('releaseDate'),
                'support': cycle.get('support'),
                'discontinued': cycle.get('discontinued'),
            }
        )
    
    def check_banner(self, banner: str) -> EOLStatus:
        """Check EOL status from a service banner.
        
        Automatically extracts product and version from banner text.
        
        Args:
            banner: Raw service banner string
            
        Returns:
            EOLStatus for detected product
        """
        if not banner:
            return EOLStatus(
                product="unknown",
                version="unknown",
                level=EOLStatusLevel.UNKNOWN,
                message="Empty banner"
            )
        
        # Try to extract product name
        product_slug = get_product_slug(banner)
        if not product_slug:
            return EOLStatus(
                product="unknown",
                version="unknown",
                level=EOLStatusLevel.UNKNOWN,
                message=f"Product not recognized in banner: {banner[:50]}..."
            )
        
        # Try to extract version
        version = self._extract_version(banner)
        if not version:
            return EOLStatus(
                product=product_slug,
                version="unknown",
                level=EOLStatusLevel.NOT_APPLICABLE,
                message=f"Version not detectable from banner: {banner[:50]}..."
            )
        
        return self.check_version(product_slug, version)
    
    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text.
        
        Args:
            text: Text containing version information
            
        Returns:
            Extracted version string or None
        """
        if not text:
            return None
        
        # Greedy pattern: matches "2.4.41", "1.18.0", "8.2p1"-style
        # tokens as well as "version 20.04.5" prefixed forms.  The first
        # capture group always contains the full dotted version.
        match = re.search(r'(?:version\s+)?(\d+\.\d+(?:\.\d+)?)', text)
        if match:
            return match.group(1)
        
        return None
    
    def get_product_cycles(self, product: str) -> Optional[List[Dict]]:
        """Get all version cycles for a product.
        
        Args:
            product: Product slug
            
        Returns:
            List of cycle data or None
        """
        return self.fetch_product_data(product)
    
    def refresh_cache(self, product: str) -> bool:
        """Delete cached data for a product so it will be re-fetched on next --setup.

        Args:
            product: Product slug

        Returns:
            True if cache entry was deleted
        """
        return self.cache.delete(product)
