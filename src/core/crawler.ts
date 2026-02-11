import axios from 'axios';
import * as cheerio from 'cheerio';
import { Route } from './types.js';
import { DISCOVERY_PATHS } from './wordlists.js';
import {
  getCachedPaths,
  getCachedExistingPaths,
  updateCache,
  getCacheStats
} from './route-cache.js';

export async function discoverRoutes(baseUrl: string): Promise<Route[]> {
  const routes: Route[] = [];
  const visited = new Set<string>();

  // Load cache and get already-searched paths
  const cachedPaths = getCachedPaths(baseUrl);
  const cachedExistingRoutes = getCachedExistingPaths(baseUrl);
  const cacheStats = getCacheStats(baseUrl);

  // Add cached existing paths to routes
  cachedExistingRoutes.forEach(entry => {
    routes.push({ path: entry.path, method: 'GET' });
  });

  // Filter out paths we've already searched
  const pathsToSearch = DISCOVERY_PATHS.filter(path => !cachedPaths.has(path));

  // Track new cache entries
  const newCacheEntries: Array<{
    path: string;
    exists: boolean;
    status?: number;
    lastChecked: string;
  }> = [];

  // Only search new paths
  if (pathsToSearch.length > 0) {
    // 1. Check Common Paths
    // We limit concurrent requests to avoid choking the target or local network
    const CHUNK_SIZE = 10;
    for (let i = 0; i < pathsToSearch.length; i += CHUNK_SIZE) {
        const chunk = pathsToSearch.slice(i, i + CHUNK_SIZE);
        const promises = chunk.map(async (path) => {
          try {
            const res = await axios.get(`${baseUrl}${path}`, { validateStatus: () => true });
            const exists = res.status !== 404;

            // Add to cache entries
            newCacheEntries.push({
              path,
              exists,
              status: res.status,
              lastChecked: new Date().toISOString()
            });

            if (exists) {
              routes.push({ path, method: 'GET' });

              // Parse robots.txt
              if (path === '/robots.txt' && typeof res.data === 'string') {
                  const lines = res.data.split('\n');
                  lines.forEach(line => {
                      const match = line.match(/^(?:Allow|Disallow):\s*(\S+)/i);
                      if (match && match[1] && match[1].startsWith('/')) {
                           routes.push({ path: match[1], method: 'GET' });
                      }
                  });
              }

              // If HTML, crawl for links
              if (typeof res.data === 'string' && res.headers['content-type']?.includes('text/html')) {
                  const $ = cheerio.load(res.data);
                  $('a').each((_, el) => {
                      const href = $(el).attr('href');
                      if (href && href.startsWith('/') && !visited.has(href)) {
                           if (!DISCOVERY_PATHS.includes(href)) {
                              routes.push({ path: href, method: 'GET' });
                           }
                      }
                  });
              }
            }
          } catch (e) {
            // Add failed path to cache as non-existent
            newCacheEntries.push({
              path,
              exists: false,
              lastChecked: new Date().toISOString()
            });
          }
        });
        await Promise.all(promises);
    }

    // Update cache with new findings
    if (newCacheEntries.length > 0) {
      updateCache(baseUrl, newCacheEntries);
    }
  }

  // Deduplicate
  const uniqueRoutes = new Map<string, Route>();
  routes.forEach(r => uniqueRoutes.set(r.path, r));
  return Array.from(uniqueRoutes.values());
}
