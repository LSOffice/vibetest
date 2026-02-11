import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

interface CacheEntry {
  path: string;
  exists: boolean;
  status?: number;
  lastChecked: string;
}

interface RouteCache {
  [baseUrlHash: string]: {
    baseUrl: string;
    entries: CacheEntry[];
  };
}

const CACHE_FILE = path.join(process.cwd(), '.vibetest-cache.json');

/**
 * Generate a hash for the baseUrl to use as a cache key
 */
function hashBaseUrl(baseUrl: string): string {
  return crypto.createHash('md5').update(baseUrl).digest('hex');
}

/**
 * Load the route cache from disk
 */
export function loadCache(): RouteCache {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch (error) {
    // If cache is corrupted or unreadable, start fresh
  }
  return {};
}

/**
 * Save the route cache to disk
 */
export function saveCache(cache: RouteCache): void {
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), 'utf-8');
  } catch (error) {
    // Silently fail if we can't save cache
  }
}

/**
 * Get cached paths for a specific baseUrl
 */
export function getCachedPaths(baseUrl: string): Set<string> {
  const cache = loadCache();
  const hash = hashBaseUrl(baseUrl);

  if (cache[hash]) {
    return new Set(cache[hash].entries.map(e => e.path));
  }

  return new Set();
}

/**
 * Get paths that exist from cache for a specific baseUrl
 */
export function getCachedExistingPaths(baseUrl: string): CacheEntry[] {
  const cache = loadCache();
  const hash = hashBaseUrl(baseUrl);

  if (cache[hash]) {
    return cache[hash].entries.filter(e => e.exists);
  }

  return [];
}

/**
 * Update cache with newly discovered paths
 */
export function updateCache(baseUrl: string, newEntries: CacheEntry[]): void {
  const cache = loadCache();
  const hash = hashBaseUrl(baseUrl);

  if (!cache[hash]) {
    cache[hash] = {
      baseUrl,
      entries: []
    };
  }

  // Merge new entries with existing ones
  const existingPaths = new Set(cache[hash].entries.map(e => e.path));

  newEntries.forEach(newEntry => {
    if (existingPaths.has(newEntry.path)) {
      // Update existing entry
      const index = cache[hash].entries.findIndex(e => e.path === newEntry.path);
      cache[hash].entries[index] = newEntry;
    } else {
      // Add new entry
      cache[hash].entries.push(newEntry);
    }
  });

  saveCache(cache);
}

/**
 * Clear cache for a specific baseUrl (or all if no baseUrl provided)
 */
export function clearCache(baseUrl?: string): void {
  if (baseUrl) {
    const cache = loadCache();
    const hash = hashBaseUrl(baseUrl);
    delete cache[hash];
    saveCache(cache);
  } else {
    // Clear all cache
    if (fs.existsSync(CACHE_FILE)) {
      fs.unlinkSync(CACHE_FILE);
    }
  }
}

/**
 * Get cache statistics for a baseUrl
 */
export function getCacheStats(baseUrl: string): {
  totalCached: number;
  existingPaths: number;
  notFoundPaths: number;
} {
  const cache = loadCache();
  const hash = hashBaseUrl(baseUrl);

  if (!cache[hash]) {
    return {
      totalCached: 0,
      existingPaths: 0,
      notFoundPaths: 0
    };
  }

  const entries = cache[hash].entries;

  return {
    totalCached: entries.length,
    existingPaths: entries.filter(e => e.exists).length,
    notFoundPaths: entries.filter(e => !e.exists).length
  };
}
