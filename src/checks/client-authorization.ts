import puppeteer from "puppeteer";
import chalk from "chalk";
import { VibeConfig, Route, Finding, RiskLevel } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * Client-Side Authorization Trust Check
 *
 * Tests if UI hides admin/privileged actions but API allows them.
 * Looks for:
 * - Hidden admin buttons that are still wired to APIs
 * - Disabled buttons that still have active endpoints
 * - Role checks only in React/Vue components
 */
export async function checkClientSideAuthorization(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n🔐 Testing Client-Side Authorization Trust..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    // Capture all network requests to find hidden API endpoints
    const apiCalls: { url: string; method: string; hidden: boolean }[] = [];

    await page.setRequestInterception(true);
    page.on("request", (request) => {
      const url = request.url();
      if (url.includes("/api/") || url.includes(config.baseUrl)) {
        apiCalls.push({
          url,
          method: request.method(),
          hidden: false,
        });
      }
      request.continue();
    });

    // Navigate to main page
    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Analyze page for authorization patterns
    const authPatterns = await page.evaluate(() => {
      const patterns: {
        hiddenElements: string[];
        disabledElements: string[];
        roleChecks: string[];
      } = {
        hiddenElements: [],
        disabledElements: [],
        roleChecks: [],
      };

      // Find hidden admin elements
      const allElements = document.querySelectorAll("*");
      allElements.forEach((el) => {
        const text = el.textContent?.toLowerCase() || "";
        const classes = el.className.toString().toLowerCase();
        const id = el.id.toLowerCase();

        // Check for admin/privileged element patterns
        if (
          text.includes("admin") ||
          text.includes("delete") ||
          text.includes("edit") ||
          classes.includes("admin") ||
          id.includes("admin")
        ) {
          const computed = window.getComputedStyle(el as Element);
          if (computed.display === "none" || computed.visibility === "hidden") {
            patterns.hiddenElements.push(
              `${el.tagName}.${el.className} - "${text.substring(0, 50)}"`,
            );
          }

          if ((el as HTMLButtonElement).disabled) {
            patterns.disabledElements.push(
              `${el.tagName}.${el.className} - "${text.substring(0, 50)}"`,
            );
          }
        }
      });

      return patterns;
    });

    // Scan all loaded JavaScript for role checks
    const scripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll("script"))
        .map((s) => s.src)
        .filter((src) => src && !src.includes("node_modules"));
    });

    for (const scriptUrl of scripts) {
      try {
        const response = await page.goto(scriptUrl, { timeout: 5000 });
        if (response) {
          const scriptContent = await response.text();

          // Look for client-side role checks
          const rolePatterns = [
            /isAdmin\s*[=:]/gi,
            /role\s*===?\s*['"]admin['"]/gi,
            /canEdit\s*[=:]/gi,
            /hasPermission\(/gi,
            /userRole\s*[=:]/gi,
            /\.role\s*===?\s*/gi,
          ];

          for (const pattern of rolePatterns) {
            const matches = scriptContent.match(pattern);
            if (matches) {
              findings.push({
                id: `client-auth-${Math.random().toString(36).substr(2, 9)}`,
                checkId: "client-authorization",
                category: "frontend",
                name: "Role Check Found in Client JavaScript",
                description: `Found authorization logic in client bundle: "${matches[0]}". Client-side checks can be bypassed. Move all authorization checks to the server. Never trust client-side role validation. (CWE-602)`,
                endpoint: scriptUrl,
                risk: "high" as RiskLevel,
                assumption:
                  "Client-side role checks are sufficient for authorization",
                reproduction: `Check script at ${scriptUrl} for pattern: ${pattern.source}`,
                fix: "Implement all authorization checks server-side",
              });

              logTestAttempt({
                check: "client-authorization",
                endpoint: scriptUrl,
                status: "VULNERABLE",
                details: `Found client-side role check: ${matches[0]}`,
              });
            }
          }
        }
      } catch (e) {
        // Skip failed script loads
      }
    }

    // Report hidden/disabled elements with potential backend endpoints
    if (authPatterns.hiddenElements.length > 0) {
      findings.push({
        id: `client-auth-${Math.random().toString(36).substr(2, 9)}`,
        checkId: "client-authorization",
        category: "frontend",
        name: "Hidden Admin Elements Detected",
        description: `Found ${authPatterns.hiddenElements.length} admin/privileged elements hidden via CSS. These may have active backend endpoints. Test if these elements trigger API calls when unhidden. Backend must enforce authorization. (CWE-602)`,
        endpoint: config.baseUrl,
        risk: "medium" as RiskLevel,
        assumption: "Hidden UI elements cannot be interacted with",
        reproduction: `Unhide elements via DevTools on ${config.baseUrl}. Hidden elements: ${authPatterns.hiddenElements.slice(0, 5).join("; ")}`,
        fix: "Ensure backend properly validates authorization for all endpoints",
      });

      logTestAttempt({
        check: "client-authorization",
        endpoint: config.baseUrl,
        status: "SUSPICIOUS",
        details: `Found ${authPatterns.hiddenElements.length} hidden admin elements`,
      });
    }

    if (authPatterns.disabledElements.length > 0) {
      findings.push({
        id: `client-auth-${Math.random().toString(36).substr(2, 9)}`,
        checkId: "client-authorization",
        category: "frontend",
        name: "Disabled Admin Elements Found",
        description: `Found ${authPatterns.disabledElements.length} disabled admin/privileged buttons. Disabled buttons can be re-enabled in DevTools. Backend authorization is required. (CWE-602)`,
        endpoint: config.baseUrl,
        risk: "medium" as RiskLevel,
        assumption: "Disabled buttons cannot be interacted with",
        reproduction: `Enable buttons via DevTools on ${config.baseUrl}. Disabled elements: ${authPatterns.disabledElements.slice(0, 5).join("; ")}`,
        fix: "Ensure backend validates authorization for all button actions",
      });
    }

    await browser.close();
  } catch (error) {
    console.log(
      chalk.yellow("  ⚠ Could not complete client authorization check"),
    );
  }

  return findings;
}
