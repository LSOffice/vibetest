import axios from 'axios';
import * as cheerio from 'cheerio';
import { Route } from './types.js';
import { DISCOVERY_PATHS } from './wordlists.js';

export async function discoverRoutes(baseUrl: string): Promise<Route[]> {
  const routes: Route[] = [];
  const visited = new Set<string>();

  // 1. Check Common Paths
  // We limit concurrent requests to avoid choking the target or local network
  const CHUNK_SIZE = 10;
  for (let i = 0; i < DISCOVERY_PATHS.length; i += CHUNK_SIZE) {
      const chunk = DISCOVERY_PATHS.slice(i, i + CHUNK_SIZE);
      const promises = chunk.map(async (path) => {
        try {
          const res = await axios.get(`${baseUrl}${path}`, { validateStatus: () => true });
          if (res.status !== 404) {
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
          // Ignore connection errors
        }
      });
      await Promise.all(promises);
  }

  // Deduplicate
  const uniqueRoutes = new Map<string, Route>();
  routes.forEach(r => uniqueRoutes.set(r.path, r));
  return Array.from(uniqueRoutes.values());
}
