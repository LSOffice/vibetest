import puppeteer from "puppeteer";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * Client-Side Routing & Route Guards Check
 *
 * Tests if route protection is only client-side:
 * - /admin, /settings, /dashboard routes
 * - Protected routes with guards in React Router / Next.js
 * - API access without UI navigation
 */
export async function checkClientRouting(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n🛣️ Testing Client-Side Routing & Route Guards..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    // Track which routes have client-side guards
    const routeGuards: { path: string; hasGuard: boolean }[] = [];

    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Analyze client-side routing code
    const routingAnalysis = await page.evaluate(() => {
      const analysis: {
        detectedRoutes: string[];
        guardPatterns: string[];
        framework?: string;
      } = {
        detectedRoutes: [],
        guardPatterns: [],
      };

      // Check for routing frameworks
      if ((window as any).__NEXT_DATA__) {
        analysis.framework = "Next.js";
      } else if ((window as any).__NUXT__) {
        analysis.framework = "Nuxt";
      }

      // Try to extract routes from window object
      const htmlText = document.documentElement.innerHTML;

      // Look for route definitions
      const routePatterns = [
        /path:\s*['"]([^'"]+)['"]/g,
        /route:\s*['"]([^'"]+)['"]/g,
        /<Route[^>]+path=['"]([^'"]+)['"]/g,
      ];

      for (const pattern of routePatterns) {
        let match;
        while ((match = pattern.exec(htmlText)) !== null) {
          if (match[1]) {
            analysis.detectedRoutes.push(match[1]);
          }
        }
      }

      return analysis;
    });

    // Scan JavaScript for route guard patterns
    const scripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll("script"))
        .map((s) => s.textContent || "")
        .join("\n");
    });

    const guardPatterns = [
      /beforeEnter\s*:/g,
      /canActivate/g,
      /requireAuth/g,
      /isAuthenticated\s*[?:]/g,
      /\s+if\s*\(!.*isAdmin\)/g,
      /\.redirect\(/g,
      /router\.push\(['"]\/login['"]\)/g,
    ];

    const foundGuards: string[] = [];
    for (const pattern of guardPatterns) {
      const matches = scripts.match(pattern);
      if (matches) {
        foundGuards.push(pattern.source);
      }
    }

    if (foundGuards.length > 0) {
      findings.push({
        id: `client-routing-${Date.now()}`,
        checkId: "client-routing",
        category: "frontend",
        name: "Client-Side Route Guards Detected",
        description: `Found ${foundGuards.length} route guard patterns in client code. These can be bypassed.`,
        endpoint: config.baseUrl,
        risk: "high",
        assumption:
          "Route guards implemented on client will prevent access to protected pages",
        reproduction:
          "Inspect JavaScript code for guard patterns and attempt direct navigation",
        fix: "Implement authorization checks on the backend API, not just client-side routing",
      });

      await logTestAttempt({
        check: "client-routing",
        endpoint: config.baseUrl,
        status: "SUSPICIOUS",
        details: `Found ${foundGuards.length} client-side guards`,
      });
    }

    await browser.close();

    // Test protected routes directly
    const protectedPaths = [
      "/admin",
      "/admin/dashboard",
      "/admin/users",
      "/dashboard",
      "/settings",
      "/profile/edit",
      "/api/admin",
      "/api/users/list",
      "/internal",
    ];

    for (const path of protectedPaths) {
      try {
        await logTestAttempt({
          check: "client-routing",
          endpoint: `GET ${path}`,
          status: "TESTING",
          details: "Direct access without UI navigation",
        });

        const response = await fetch(`${config.baseUrl}${path}`, {
          credentials: "include",
        });

        // If we get 200, the route is accessible without client routing
        if (response.status === 200) {
          findings.push({
            id: `client-routing-${Date.now()}-${path}`,
            checkId: "client-routing",
            category: "backend",
            name: "Protected Route Accessible Without Client Navigation",
            description: `The route ${path} is accessible directly without going through client-side routing guards.`,
            endpoint: `GET ${path}`,
            risk: "high",
            assumption:
              "Protected routes require client-side navigation through route guards",
            reproduction: `Make a direct GET request to ${path}`,
            fix: "Backend must enforce authorization on all protected routes. Don't rely on client routing to hide them.",
          });

          await logTestAttempt({
            check: "client-routing",
            endpoint: `GET ${path}`,
            status: "VULNERABLE",
            details: "Accessible without auth",
          });
        } else if (response.status === 401 || response.status === 403) {
          // Good - backend is protecting the route
          await logTestAttempt({
            check: "client-routing",
            endpoint: `GET ${path}`,
            status: "SECURE",
            details: `Protected by backend (${response.status})`,
          });
        }
      } catch (error: any) {
        // 404 is fine - route doesn't exist
        if (error.response?.status === 404) {
          await logTestAttempt({
            check: "client-routing",
            endpoint: `GET ${path}`,
            status: "INFO",
            details: "Route not found",
          });
        }
      }
    }
  } catch (error) {
    console.log(chalk.yellow("  ⚠ Could not complete client routing check"));
  }

  return findings;
}
