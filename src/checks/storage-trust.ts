import puppeteer from "puppeteer";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";
import axios from "axios";
import { getRateLimitInstance } from "../core/rate-limit.js";

/**
 * localStorage/sessionStorage Trust Check
 *
 * Tests if server trusts client storage:
 * - Auth state stored client-side
 * - Role/permission flags in storage
 * - Modifying storage affects server behavior
 */
export async function checkStorageTrust(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n💾 Testing localStorage/sessionStorage Trust..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Inspect current storage
    const storageAnalysis = await page.evaluate(() => {
      const analysis: {
        localStorage: Record<string, string>;
        sessionStorage: Record<string, string>;
        sensitiveKeys: string[];
      } = {
        localStorage: {},
        sessionStorage: {},
        sensitiveKeys: [],
      };

      // Extract localStorage
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) {
          const value = window.localStorage.getItem(key) || "";
          analysis.localStorage[key] = value;

          // Check if key looks sensitive
          const keyLower = key.toLowerCase();
          if (
            keyLower.includes("auth") ||
            keyLower.includes("token") ||
            keyLower.includes("role") ||
            keyLower.includes("admin") ||
            keyLower.includes("permission") ||
            keyLower.includes("user") ||
            keyLower.includes("session")
          ) {
            analysis.sensitiveKeys.push(`localStorage.${key}`);
          }
        }
      }

      // Extract sessionStorage
      for (let i = 0; i < window.sessionStorage.length; i++) {
        const key = window.sessionStorage.key(i);
        if (key) {
          const value = window.sessionStorage.getItem(key) || "";
          analysis.sessionStorage[key] = value;

          const keyLower = key.toLowerCase();
          if (
            keyLower.includes("auth") ||
            keyLower.includes("token") ||
            keyLower.includes("role") ||
            keyLower.includes("admin") ||
            keyLower.includes("permission")
          ) {
            analysis.sensitiveKeys.push(`sessionStorage.${key}`);
          }
        }
      }

      return analysis;
    });

    // Report sensitive data in storage
    if (storageAnalysis.sensitiveKeys.length > 0) {
      findings.push({
        id: "storage-trust-sensitive-data",
        checkId: "storage-trust",
        category: "frontend",
        name: "Sensitive Data Stored in Client Storage",
        description: `Found ${storageAnalysis.sensitiveKeys.length} sensitive keys in localStorage/sessionStorage. These can be manipulated by users.`,
        endpoint: config.baseUrl,
        risk: "high",
        assumption: "Client storage is not accessible to attackers",
        reproduction: `Check browser localStorage/sessionStorage for keys: ${storageAnalysis.sensitiveKeys.join(", ")}`,
        fix: "Never store authorization state, roles, or permissions in client storage. Backend must validate independently.",
      });

      logTestAttempt({
        check: "storage-trust",
        endpoint: config.baseUrl,
        status: "VULNERABLE",
        details: `Found ${storageAnalysis.sensitiveKeys.length} sensitive storage keys`,
      });
    }

    // Test modifying role/auth flags
    const testModifications = [
      { key: "isAdmin", value: "true" },
      { key: "role", value: "admin" },
      { key: "userRole", value: "admin" },
      {
        key: "permissions",
        value: JSON.stringify(["admin", "delete", "edit"]),
      },
      { key: "isAuthenticated", value: "true" },
      { key: "user", value: JSON.stringify({ role: "admin", isAdmin: true }) },
    ];

    for (const mod of testModifications) {
      // Set the modified value
      await page.evaluate(
        (key, value) => {
          localStorage.setItem(key, value);
          sessionStorage.setItem(key, value);
        },
        mod.key,
        mod.value,
      );

      // Reload to see if app reads it
      await page.reload({ waitUntil: "networkidle0" }).catch(() => {});

      // Check if any API calls happen with this new state
      const apiCalls: string[] = [];
      page.on("request", (request) => {
        if (request.url().includes("/api/")) {
          apiCalls.push(request.url());
        }
      });

      // Wait a bit for any API calls
      await page.waitForFunction(() => true, { timeout: 2000 });

      if (apiCalls.length > 0) {
        findings.push({
          id: `storage-trust-modified-${mod.key}`,
          checkId: "storage-trust",
          category: "frontend",
          name: `Application Reads Modified Storage Key: ${mod.key}`,
          description: `After setting ${mod.key}=${mod.value} in storage, the application made API calls, suggesting it reads and trusts this client-side value.`,
          endpoint: config.baseUrl,
          risk: "high",
          assumption:
            "Client storage modifications don't affect server behavior",
          reproduction: `Set localStorage.${mod.key} = "${mod.value}" and observe API behavior`,
          fix: "Backend must not trust client storage values. Validate all authorization server-side.",
        });

        logTestAttempt({
          check: "storage-trust",
          endpoint: config.baseUrl,
          status: "VULNERABLE",
          details: `App responds to modified ${mod.key}`,
        });
      }
    }

    await browser.close();

    // Test if backend accepts manipulated storage values
    const axiosInstance = getRateLimitInstance(config);

    for (const route of routes.slice(0, 5)) {
      if (route.method === "GET") {
        try {
          // Send request with fake auth header from "localStorage"
          const response = await axiosInstance.get(route.path, {
            headers: {
              "X-User-Role": "admin",
              "X-Is-Admin": "true",
              "X-Permissions": "admin,delete,edit",
            },
            validateStatus: () => true,
          });

          if (response.status === 200) {
            findings.push({
              id: "storage-trust-header-bypass",
              checkId: "storage-trust",
              category: "backend",
              name: "Backend May Trust Client Headers",
              description: `Endpoint accepted custom headers (X-User-Role: admin) that might come from client storage.`,
              endpoint: `GET ${route.path}`,
              risk: "medium",
              assumption: "Backend validates all authorization server-side",
              reproduction: `Send GET ${route.path} with headers: X-User-Role: admin, X-Is-Admin: true`,
              fix: "Backend should never trust X-* headers for authorization. Use secure session tokens only.",
            });
          }
        } catch (error: any) {
          // Errors are fine
        }
      }
    }
  } catch (error) {
    console.log(chalk.yellow("  ⚠ Could not complete storage trust check"));
  }

  return findings;
}
