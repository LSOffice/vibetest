import puppeteer from "puppeteer";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * SSR Boundary Leaks Check (Next.js / Nuxt)
 *
 * Tests for server-side data leaked to client:
 * - __NEXT_DATA__ containing secrets
 * - Server props with sensitive data
 * - Internal API responses in hydration
 */
export async function checkSSRLeaks(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n🔍 Testing SSR Boundary Leaks..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Extract SSR data
    const ssrAnalysis = await page.evaluate(() => {
      const analysis: {
        framework?: string;
        nextData?: any;
        nuxtData?: any;
        sensitiveKeys: string[];
        suspiciousValues: string[];
      } = {
        sensitiveKeys: [],
        suspiciousValues: [],
      };

      // Check for Next.js
      if ((window as any).__NEXT_DATA__) {
        analysis.framework = "Next.js";
        analysis.nextData = (window as any).__NEXT_DATA__;
      }

      // Check for Nuxt
      if ((window as any).__NUXT__) {
        analysis.framework = "Nuxt";
        analysis.nuxtData = (window as any).__NUXT__;
      }

      // Recursively search for sensitive patterns
      const sensitivePatterns = [
        "password",
        "secret",
        "api_key",
        "apiKey",
        "private",
        "token",
        "credentials",
        "auth",
        "session",
        "jwt",
        "bearer",
        "database",
        "db_",
        "DB_",
        "MONGO",
        "POSTGRES",
        "MYSQL",
        "AWS_",
        "STRIPE_SECRET",
        "OPENAI_API_KEY",
      ];

      const checkObject = (obj: any, path: string = "") => {
        if (!obj || typeof obj !== "object") return;

        for (const [key, value] of Object.entries(obj)) {
          const fullPath = path ? `${path}.${key}` : key;
          const keyLower = key.toLowerCase();

          // Check if key name is sensitive
          for (const pattern of sensitivePatterns) {
            if (keyLower.includes(pattern.toLowerCase())) {
              analysis.sensitiveKeys.push(fullPath);

              // Check if value looks sensitive
              if (typeof value === "string") {
                if (
                  value.length > 10 &&
                  (value.startsWith("sk_") ||
                    value.startsWith("pk_") ||
                    value.match(/^[A-Za-z0-9_\-]{20,}$/) ||
                    value.startsWith("eyJ"))
                ) {
                  analysis.suspiciousValues.push(
                    `${fullPath}: ${value.substring(0, 20)}...`,
                  );
                }
              }
            }
          }

          // Recurse into nested objects
          if (typeof value === "object" && value !== null) {
            checkObject(value, fullPath);
          }
        }
      };

      if (analysis.nextData) {
        checkObject(analysis.nextData, "__NEXT_DATA__");
      }
      if (analysis.nuxtData) {
        checkObject(analysis.nuxtData, "__NUXT__");
      }

      return analysis;
    });

    // Check initial HTML for embedded data
    const htmlContent = await page.content();

    // Look for sensitive patterns in HTML
    const htmlPatterns = [
      /sk_live_[A-Za-z0-9]+/g, // Stripe secret keys
      /sk_test_[A-Za-z0-9]+/g, // Stripe test keys
      /pk_live_[A-Za-z0-9]+/g, // Stripe publishable (still shouldn't be in SSR data)
      /Bearer\s+eyJ[A-Za-z0-9_\-]+\./g, // JWT tokens
      /mongodb:\/\/[^\s"']+/g, // MongoDB URLs
      /postgres:\/\/[^\s"']+/g, // Postgres URLs
      /mysql:\/\/[^\s"']+/g, // MySQL URLs
      /"apiKey"\s*:\s*"[^"]{20,}"/g, // API keys in JSON
      /"secret"\s*:\s*"[^"]{10,}"/g, // Secrets in JSON
    ];

    const htmlLeaks: string[] = [];
    for (const pattern of htmlPatterns) {
      const matches = htmlContent.match(pattern);
      if (matches) {
        htmlLeaks.push(...matches.map((m) => m.substring(0, 50) + "..."));
      }
    }

    // Report findings
    if (ssrAnalysis.framework) {
      findings.push({
        id: `ssr-framework-${Date.now()}`,
        checkId: "ssr-leaks",
        category: "frontend",
        name: `${ssrAnalysis.framework} SSR Detected`,
        description: `Application uses ${ssrAnalysis.framework}. Checking for server-side data leaks...`,
        endpoint: config.baseUrl,
        risk: "low",
        assumption:
          "Sensitive data should never be passed to client components",
        reproduction: "Check __NEXT_DATA__ or __NUXT__ objects in browser",
        fix: "Ensure sensitive data is never included in SSR props. Use server-only functions.",
      });
    }

    if (ssrAnalysis.sensitiveKeys.length > 0) {
      findings.push({
        id: `ssr-keys-${Date.now()}`,
        checkId: "ssr-leaks",
        category: "frontend",
        name: "Sensitive Keys Found in SSR Data",
        description: `Found ${ssrAnalysis.sensitiveKeys.length} sensitive key names in server-side rendered data.`,
        endpoint: config.baseUrl,
        risk: "high",
        assumption: "SSR data should not contain sensitive key names",
        reproduction: `Found keys: ${ssrAnalysis.sensitiveKeys.slice(0, 3).join(", ")}`,
        fix: "Never include passwords, tokens, secrets, or internal data in SSR props. Use server-only functions.",
      });

      logTestAttempt({
        checkId: "ssr-leaks",
        status: "VULNERABLE",
        message: `Found ${ssrAnalysis.sensitiveKeys.length} sensitive keys in SSR data`,
      });
    }

    if (ssrAnalysis.suspiciousValues.length > 0) {
      findings.push({
        id: `ssr-values-${Date.now()}`,
        checkId: "ssr-leaks",
        category: "frontend",
        name: "Secrets Exposed in SSR Data",
        description: `Found ${ssrAnalysis.suspiciousValues.length} values that look like actual secrets in client-side SSR data!`,
        endpoint: config.baseUrl,
        risk: "critical",
        assumption: "Secrets should never be exposed to the client",
        reproduction: `Values found: ${ssrAnalysis.suspiciousValues.slice(0, 2).join("; ")}`,
        fix: "URGENT: Remove all secrets from SSR data. Use environment variables only on the server side. Never expose API keys to the client.",
      });

      logTestAttempt({
        checkId: "ssr-leaks",
        status: "CRITICAL",
        message: `Exposed secrets in SSR data!`,
      });
    }

    if (htmlLeaks.length > 0) {
      findings.push({
        id: `ssr-html-${Date.now()}`,
        checkId: "ssr-leaks",
        category: "frontend",
        name: "Secrets Found in HTML Source",
        description: `Found ${htmlLeaks.length} potential secrets directly in HTML source code!`,
        endpoint: config.baseUrl,
        risk: "critical",
        assumption: "Secrets should not be embedded in HTML",
        reproduction: `Patterns found: ${htmlLeaks.slice(0, 2).join("; ")}`,
        fix: "CRITICAL: Secrets are exposed in HTML. These may be database URLs, API keys, or tokens. Remove immediately.",
      });

      logTestAttempt({
        checkId: "ssr-leaks",
        status: "CRITICAL",
        message: `Secrets in HTML source!`,
      });
    }

    await browser.close();
  } catch (error) {
    console.log(chalk.yellow("  ⚠ Could not complete SSR leak check"));
  }

  return findings;
}
