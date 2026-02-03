import axios from "axios";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";
import { getRateLimitInstance } from "../core/rate-limit.js";

/**
 * API Trust in Client-Generated Data Check
 *
 * Tests if backend trusts client-calculated values like:
 * - Prices, totals, discounts
 * - Status flags
 * - Derived/computed fields
 */
export async function checkClientDataTrust(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n💰 Testing API Trust in Client-Generated Data..."));

  const postRoutes = routes.filter(
    (r) => r.method === "POST" || r.method === "PUT" || r.method === "PATCH",
  );

  for (const route of postRoutes) {
    // Look for routes that might have client-generated data
    const suspiciousFields = [
      "price",
      "total",
      "amount",
      "discount",
      "subtotal",
      "tax",
      "cost",
      "balance",
      "status",
      "isActive",
      "isAdmin",
      "role",
      "permissions",
      "verified",
      "approved",
    ];

    // Check if route might accept these fields
    const routeLower = route.path.toLowerCase();
    const mightHaveCalculations =
      routeLower.includes("order") ||
      routeLower.includes("cart") ||
      routeLower.includes("checkout") ||
      routeLower.includes("payment") ||
      routeLower.includes("purchase") ||
      routeLower.includes("user") ||
      routeLower.includes("profile");

    if (!mightHaveCalculations) continue;

    const axiosInstance = getRateLimitInstance(config);

    // Test with manipulated client-generated fields
    for (const field of suspiciousFields) {
      const testPayloads = [
        { [field]: 0 }, // Zero value
        { [field]: -999 }, // Negative value
        { [field]: 999999999 }, // Extremely high value
        { [field]: 0.01 }, // Minimal value
        { [field]: true }, // For boolean flags
        { [field]: "admin" }, // For role/status fields
      ];

      for (const payload of testPayloads) {
        try {
          logTestAttempt({
            check: "client-data-trust",
            endpoint: `${route.method} ${route.path}`,
            status: "TESTING",
            details: `Testing ${field} manipulation`,
          });

          const response = await axiosInstance.request({
            method: route.method,
            url: route.path,
            data: payload,
            validateStatus: () => true,
          });

          // If server accepts the request without validation error
          if (response.status >= 200 && response.status < 300) {
            findings.push({
              id: `cdt-${route.path}-${field}`,
              checkId: "client-data-trust",
              category: "backend",
              name: `Server Accepts Client-Calculated ${field}`,
              description: `Server accepted ${field}=${JSON.stringify(payload[field])} without validation. This suggests the server trusts client-generated data.`,
              endpoint: `${route.method} ${route.path}`,
              risk: "high",
              assumption: "Server validates financial and authorization data",
              reproduction: `Send ${JSON.stringify(payload)} to ${route.method} ${route.path}`,
              fix: `Always recalculate ${field} on the server. Never trust client-provided calculations for financial or authorization data.`,
            });

            logTestAttempt({
              check: "client-data-trust",
              endpoint: `${route.method} ${route.path}`,
              status: "VULNERABLE",
              details: `Server accepted manipulated ${field}`,
            });

            // Only flag once per field per endpoint
            break;
          }
        } catch (error: any) {
          // Network errors or rejections are fine
          if (
            error.response?.status === 400 ||
            error.response?.status === 422
          ) {
            // Validation error is good - server is checking
            logTestAttempt({
              check: "client-data-trust",
              endpoint: `${route.method} ${route.path}`,
              status: "SECURE",
              details: `Server validated ${field}`,
            });
          }
        }
      }
    }
  }

  return findings;
}
