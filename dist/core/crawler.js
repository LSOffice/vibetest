"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.discoverRoutes = discoverRoutes;
const axios_1 = __importDefault(require("axios"));
const cheerio = __importStar(require("cheerio"));
const wordlists_js_1 = require("./wordlists.js");
async function discoverRoutes(baseUrl) {
    const routes = [];
    const visited = new Set();
    // 1. Check Common Paths
    // We limit concurrent requests to avoid choking the target or local network
    const CHUNK_SIZE = 10;
    for (let i = 0; i < wordlists_js_1.DISCOVERY_PATHS.length; i += CHUNK_SIZE) {
        const chunk = wordlists_js_1.DISCOVERY_PATHS.slice(i, i + CHUNK_SIZE);
        const promises = chunk.map(async (path) => {
            try {
                const res = await axios_1.default.get(`${baseUrl}${path}`, { validateStatus: () => true });
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
                                if (!wordlists_js_1.DISCOVERY_PATHS.includes(href)) {
                                    routes.push({ path: href, method: 'GET' });
                                }
                            }
                        });
                    }
                }
            }
            catch (e) {
                // Ignore connection errors
            }
        });
        await Promise.all(promises);
    }
    // Deduplicate
    const uniqueRoutes = new Map();
    routes.forEach(r => uniqueRoutes.set(r.path, r));
    return Array.from(uniqueRoutes.values());
}
