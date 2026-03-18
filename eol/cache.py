"""
NetWatch EOL Cache Manager Module.

This module provides local JSON caching for End-of-Life API responses
with configurable TTL (Time To Live). Caching reduces API calls and
improves performance for repeated scans.

Exports:
    CacheManager: Main class for cache operations
    CacheEntry: Dataclass representing a cached entry

Example:
    from eol.cache import CacheManager
    cache = CacheManager()
    
    # Store data
    cache.set("ubuntu", eol_data)
    
    # Retrieve data
    data = cache.get("ubuntu")
    if data:
        print("Cache hit!")
"""

import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from config.settings import Settings, CACHE_DIR

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached EOL data entry.
    
    Attributes:
        product: Product slug/name
        data: The cached EOL data
        timestamp: When the data was cached
        ttl_hours: Cache time-to-live in hours
    """
    product: str
    data: Dict[str, Any]
    timestamp: str
    ttl_hours: int
    
    @property
    def cached_at(self) -> datetime:
        """Parse the timestamp into a datetime object."""
        return datetime.fromisoformat(self.timestamp)
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        expiry = self.cached_at + timedelta(hours=self.ttl_hours)
        return datetime.now() > expiry
    
    def age_hours(self) -> float:
        """Calculate the age of the cache entry in hours."""
        return (datetime.now() - self.cached_at).total_seconds() / 3600


class CacheManager:
    """Manages local JSON caching for EOL API responses.
    
    This class provides methods for storing and retrieving EOL data
    with automatic TTL-based expiration. Cache files are stored as
    JSON in the configured cache directory.
    
    Attributes:
        cache_dir: Path to cache directory
        ttl_hours: Default TTL for cache entries
        
    Example:
        cache = CacheManager(ttl_hours=24)
        
        # Save data
        cache.set("ubuntu", {"versions": [...]})
        
        # Load data (returns None if expired or missing)
        data = cache.get("ubuntu")
        
        # Check if cache exists
        if cache.has("ubuntu"):
            print("Cache exists")
    """
    
    def __init__(
        self, 
        cache_dir: Optional[str] = None,
        ttl_hours: Optional[int] = None,
        settings: Optional[Settings] = None
    ):
        """Initialize the cache manager.
        
        Args:
            cache_dir: Path to cache directory (uses default if None)
            ttl_hours: Default TTL in hours (uses settings if None)
            settings: Settings configuration object
        """
        self.settings = settings or Settings()
        self.cache_dir = Path(cache_dir or CACHE_DIR)
        self.ttl_hours = ttl_hours or self.settings.cache_ttl_hours
        
        # Ensure cache directory exists
        self._ensure_cache_dir()
        
        logger.debug(f"CacheManager initialized (dir={self.cache_dir}, "
                    f"ttl={self.ttl_hours}h)")
    
    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory ready: {self.cache_dir}")
        except OSError as e:
            logger.error(f"Failed to create cache directory: {e}")
            raise
    
    def _get_cache_path(self, product: str) -> Path:
        """Get the file path for a product's cache file.
        
        Args:
            product: Product slug/name
            
        Returns:
            Path to cache file
        """
        # Sanitize product name for filename
        safe_name = "".join(c for c in product if c.isalnum() or c in '-_').lower()
        return self.cache_dir / f"{safe_name}.json"
    
    def get(self, product: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached data for a product.
        
        Returns the cached data if it exists and hasn't expired,
        otherwise returns None.
        
        Args:
            product: Product slug/name
            
        Returns:
            Cached data dictionary or None
        """
        cache_path = self._get_cache_path(product)
        
        if not cache_path.exists():
            logger.debug(f"Cache miss for {product} (file not found)")
            return None
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                entry_dict = json.load(f)
            
            entry = CacheEntry(**entry_dict)
            
            if entry.is_expired():
                logger.debug(f"Cache expired for {product} "
                           f"(age={entry.age_hours():.1f}h, ttl={entry.ttl_hours}h)")
                return None
            
            logger.debug(f"Cache hit for {product} "
                        f"(age={entry.age_hours():.1f}h)")
            return entry.data
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Corrupted cache file for {product}: {e}")
            # Remove corrupted cache file
            try:
                cache_path.unlink()
            except OSError:
                pass
            return None
        except Exception as e:
            logger.error(f"Error reading cache for {product}: {e}")
            return None
    
    def set(
        self, 
        product: str, 
        data: Dict[str, Any],
        ttl_hours: Optional[int] = None
    ) -> bool:
        """Store data in cache for a product.
        
        Args:
            product: Product slug/name
            data: Data to cache
            ttl_hours: Override TTL for this entry
            
        Returns:
            True if successfully cached, False otherwise
        """
        cache_path = self._get_cache_path(product)
        ttl = ttl_hours or self.ttl_hours
        
        entry = CacheEntry(
            product=product,
            data=data,
            timestamp=datetime.now().isoformat(),
            ttl_hours=ttl
        )
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(entry), f, indent=2)
            logger.debug(f"Cached {product} (ttl={ttl}h)")
            return True
        except Exception as e:
            logger.error(f"Failed to cache {product}: {e}")
            return False
    
    def has(self, product: str, check_expired: bool = True) -> bool:
        """Check if cache exists for a product.
        
        Args:
            product: Product slug/name
            check_expired: If True, returns False for expired entries
            
        Returns:
            True if valid cache exists
        """
        if check_expired:
            return self.get(product) is not None
        else:
            return self._get_cache_path(product).exists()
    
    def delete(self, product: str) -> bool:
        """Delete cache for a product.
        
        Args:
            product: Product slug/name
            
        Returns:
            True if file was deleted or didn't exist
        """
        cache_path = self._get_cache_path(product)
        try:
            if cache_path.exists():
                cache_path.unlink()
                logger.debug(f"Deleted cache for {product}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete cache for {product}: {e}")
            return False
    
    def clear(self) -> int:
        """Clear all cached files.
        
        Returns:
            Number of files deleted
        """
        count = 0
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                    count += 1
                except OSError as e:
                    logger.warning(f"Failed to delete {cache_file}: {e}")
            logger.info(f"Cleared {count} cache files")
            return count
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return count
    
    def list_cached(self) -> Dict[str, dict]:
        """List all cached products with metadata.
        
        Returns:
            Dictionary mapping product names to cache info
        """
        cached = {}
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        entry_dict = json.load(f)
                    entry = CacheEntry(**entry_dict)
                    cached[entry.product] = {
                        'age_hours': round(entry.age_hours(), 2),
                        'ttl_hours': entry.ttl_hours,
                        'expired': entry.is_expired(),
                        'file': str(cache_file.name),
                    }
                except Exception as e:
                    logger.debug(f"Error reading {cache_file}: {e}")
        except Exception as e:
            logger.error(f"Failed to list cache: {e}")
        
        return cached
    
    def get_stats(self) -> Dict[str, any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        cached = self.list_cached()
        total = len(cached)
        expired = sum(1 for info in cached.values() if info['expired'])
        
        # Calculate total size
        total_size = 0
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                total_size += cache_file.stat().st_size
        except Exception:
            pass
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'valid_entries': total - expired,
            'total_size_bytes': total_size,
            'cache_dir': str(self.cache_dir),
            'default_ttl_hours': self.ttl_hours,
        }
    
    def cleanup_expired(self) -> int:
        """Remove all expired cache entries.
        
        Returns:
            Number of expired entries removed
        """
        count = 0
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        entry_dict = json.load(f)
                    entry = CacheEntry(**entry_dict)
                    
                    if entry.is_expired():
                        cache_file.unlink()
                        count += 1
                        logger.debug(f"Cleaned up expired cache: {entry.product}")
                except Exception as e:
                    logger.debug(f"Error checking {cache_file}: {e}")
            
            logger.info(f"Cleaned up {count} expired cache entries")
            return count
        except Exception as e:
            logger.error(f"Failed to cleanup cache: {e}")
            return count
