import { Check, Finding, RiskLevel, VibeConfig, Route } from "../core/types.js";
import chalk from "chalk";
import { logTestAttempt } from "../core/logger.js";
import axios from "axios";

export async function checkAuthRedirects(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n🔀 Testing OAuth/Auth Redirect Handling..."));

  const axiosInstance = axios.create({
    baseURL: config.baseUrl,
    timeout: 10000,
  });

  // Find auth-related routes
  const authRoutes = routes.filter(
    (r) =>
      r.path.includes("auth") ||
      r.path.includes("login") ||
      r.path.includes("signin") ||
      r.path.includes("signup") ||
      r.path.includes("logout") ||
      r.path.includes("oauth") ||
      r.path.includes("callback"),
  );

  // Common redirect parameter names
  const redirectParams = [
    "redirect",
    "redirect_uri",
    "redirectUri",
    "return",
    "returnTo",
    "return_to",
    "next",
    "url",
    "destination",
    "continue",
    "successUrl",
    "failureUrl",
  ];

  // Test redirect values
  const testRedirects = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/steal",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/\\evil.com",
    "https:evil.com",
  ];

  for (const route of authRoutes) {
    for (const param of redirectParams) {
      for (const redirectValue of testRedirects) {
        try {
          logTestAttempt({
            check: "auth-redirects",
            endpoint: `${route.method} ${route.path}`,
            status: "TESTING",
            details: `${param}=${redirectValue}`,
          });

          const response = await axiosInstance.request({
            method: route.method,
            url: route.path,
            params: {
              [param]: redirectValue,
            },
            validateStatus: () => true,
            maxRedirects: 0, // Don't follow redirects
          });

          // Check if server attempts redirect
          if (response.status >= 300 && response.status < 400) {
            const location = response.headers["location"];

            // Check if redirecting to our test value
            if (location && location.includes(redirectValue)) {
              findings.push({
                id: `auth-redirect-${route.path}-${param}`,
                checkId: "auth-redirects",
                category: "backend",
                name: "Unvalidated Redirect in Auth Flow",
                description: `Endpoint redirects to arbitrary URLs via ${param} parameter. This can be used in phishing attacks.`,
                endpoint: `${route.method} ${route.path}?${param}=${redirectValue}`,
                risk: "high",
                assumption: "All redirect URLs are validated by the server",
                reproduction: `curl "${route.path}?${param}=${redirectValue}"`,
                fix: "Validate all redirect URLs against an allowlist. Only allow relative URLs or same-origin absolute URLs.",
              });

              logTestAttempt({
                check: "auth-redirects",
                endpoint: `${route.method} ${route.path}`,
                status: "VULNERABLE",
                details: `Open redirect via ${param}`,
              });

              // Only report once per param per route
              break;
            }
          }

          // Also check response body for redirect URL (SPA patterns)
          if (response.data && typeof response.data === "string") {
            if (response.data.includes(redirectValue)) {
              findings.push({
                id: `auth-redirect-reflected-${route.path}-${param}`,
                checkId: "auth-redirects",
                category: "backend",
                name: "Redirect URL Reflected in Response",
                description: `The ${param} parameter value is reflected in the response. May be used for client-side redirect.`,
                endpoint: `${route.method} ${route.path}?${param}=${redirectValue}`,
                risk: "medium",
                assumption:
                  "Redirect parameters are validated before being returned to the client",
                reproduction: `curl "${route.path}?${param}=${redirectValue}" | grep "${redirectValue}"`,
                fix: "If using client-side redirects, validate URLs on the server and only return validated destinations.",
              });
            }
          }
        } catch (error: any) {
          // Network errors are fine
        }
      }
    }
  }

  // Test POST redirects (less common but possible)
  for (const route of authRoutes.filter((r) => r.method === "POST")) {
    for (const param of redirectParams) {
      try {
        const response = await axiosInstance.post(
          route.path,
          {
            [param]: "https://evil.com",
            username: "test",
            password: "test",
          },
          {
            validateStatus: () => true,
            maxRedirects: 0,
          },
        );

        if (response.status >= 300 && response.status < 400) {
          const location = response.headers["location"];
          if (location && location.includes("evil.com")) {
            findings.push({
              id: `auth-redirect-post-${route.path}`,
              checkId: "auth-redirects",
              category: "backend",
              name: "POST-Based Open Redirect in Auth",
              description: `POST request to ${route.path} accepts redirect parameter in body.`,
              endpoint: `POST ${route.path}`,
              risk: "high",
              assumption: "Redirect parameters in POST bodies are validated",
              reproduction: `curl -X POST "${route.path}" -d "redirect=https://evil.com"`,
              fix: "Validate redirect URLs in POST bodies. This is especially dangerous in login flows.",
            });
          }
        }
      } catch (error: any) {
        // Errors are fine
      }
    }
  }

  return findings;
}
