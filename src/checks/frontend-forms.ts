import { Check, Finding } from "../core/types.js";
import * as cheerio from "cheerio";

export const frontendFormsCheck: Check = {
  id: "frontend-forms",
  name: "Frontend Forms & Input Security",
  description:
    "Analyzes HTML forms for missing CSRF tokens, autocomplete on passwords, and exposed data",
  async run({ axios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Target HTML pages (non-API routes)
    const htmlPages = discoveredRoutes.filter(
      (r) =>
        r.method === "GET" &&
        !r.path.startsWith("/api/") &&
        !r.path.includes("."), // Skip static files
    );

    for (const route of htmlPages) {
      try {
        const res = await axios.get(route.path, {
          validateStatus: () => true,
          headers: { Accept: "text/html" },
        });

        if (
          res.status !== 200 ||
          !res.headers["content-type"]?.includes("text/html")
        ) {
          continue;
        }

        const $ = cheerio.load(res.data);

        // 1. Check forms for CSRF tokens
        $("form").each((_, form) => {
          const $form = $(form);
          const action = $form.attr("action") || route.path;
          const method = ($form.attr("method") || "GET").toUpperCase();

          // Only check POST/PUT/PATCH forms
          if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return;

          // Look for CSRF token (common names)
          const hasCSRF =
            $form.find(
              'input[name*="csrf"], input[name*="token"], input[name="_token"]',
            ).length > 0;

          if (!hasCSRF) {
            findings.push({
              id: `missing-csrf-${route.path}-${action}`,
              checkId: "frontend-forms",
              category: "frontend",
              name: "Missing CSRF Token on Form",
              endpoint: `${route.path} -> ${action}`,
              risk: "medium",
              description: `A ${method} form submitting to ${action} has no visible CSRF token field.`,
              assumption:
                "Forms are protected by SameSite cookies or developer forgot CSRF entirely.",
              reproduction: `Visit ${route.path} and inspect the form.`,
              fix: "Add CSRF tokens to all state-changing forms. Use next-csrf or csurf middleware.",
            });
          }
        });

        // 2. Check password fields for autocomplete
        $('input[type="password"]').each((_, input) => {
          const $input = $(input);
          const autocomplete = $input.attr("autocomplete");

          if (
            !autocomplete ||
            (autocomplete !== "new-password" &&
              autocomplete !== "current-password")
          ) {
            findings.push({
              id: `password-autocomplete-${route.path}`,
              checkId: "frontend-forms",
              category: "frontend",
              name: "Password Field Allows Autocomplete",
              endpoint: route.path,
              risk: "low",
              description: `A password input on ${route.path} doesn't explicitly set autocomplete, potentially allowing browsers to save it inappropriately.`,
              assumption: "Browser defaults are secure enough.",
              reproduction: `Visit ${route.path} and inspect password input.`,
              fix: 'Set autocomplete="current-password" or "new-password" explicitly.',
            });
          }
        });

        // 3. Check for hidden inputs with sensitive data
        $('input[type="hidden"]').each((_, input) => {
          const $input = $(input);
          const name = $input.attr("name")?.toLowerCase() || "";
          const value = $input.attr("value") || "";

          const sensitivePatterns = [
            "token",
            "secret",
            "key",
            "password",
            "api",
          ];
          const isSensitive = sensitivePatterns.some((p) => name.includes(p));

          if (isSensitive && value.length > 10) {
            findings.push({
              id: `exposed-hidden-${route.path}-${name}`,
              checkId: "frontend-forms",
              category: "frontend",
              name: "Sensitive Data in Hidden Field",
              endpoint: route.path,
              risk: "high",
              description: `Found a hidden input named "${name}" with a ${value.length}-character value. Hidden fields are visible in HTML source.`,
              assumption: "Users won't view source or use DevTools.",
              reproduction: `View source of ${route.path} and search for "${name}"`,
              fix: "Never put secrets in hidden fields. Use server-side sessions instead.",
            });
          }
        });

        // 4. Check for client-side validation only (no server-side backup)
        const hasClientValidation =
          $("input[required], input[pattern], input[min], input[max]").length >
          0;
        const forms = $("form");

        if (hasClientValidation && forms.length > 0) {
          // This is a heuristic - we can't know if server validates without testing
          // But we can flag it as a reminder
          findings.push({
            id: `client-validation-${route.path}`,
            checkId: "frontend-forms",
            category: "frontend",
            name: "Client-Side Validation Detected (Verify Server-Side)",
            endpoint: route.path,
            risk: "low",
            description: `HTML5 validation attributes (required, pattern, etc.) are present. Ensure server-side validation exists too.`,
            assumption: "Client-side validation is sufficient.",
            reproduction: `Disable JavaScript and submit forms on ${route.path}`,
            fix: "Always validate on the server. Client validation is UX, not security.",
          });
        }

        // 5. Check for forms with GET method for sensitive operations
        $('form[method="GET"], form[method="get"]').each((_, form) => {
          const $form = $(form);
          const action = $form.attr("action") || route.path;
          const hasPasswordField =
            $form.find('input[type="password"]').length > 0;

          if (hasPasswordField) {
            findings.push({
              id: `get-form-password-${route.path}`,
              checkId: "frontend-forms",
              category: "frontend",
              name: "Password Form Using GET Method",
              endpoint: `${route.path} -> ${action}`,
              risk: "high",
              description: `A form with a password field uses GET method, exposing credentials in URL/logs.`,
              assumption: "It doesn't matter if passwords appear in URLs.",
              reproduction: `Submit the form on ${route.path}`,
              fix: "Change method to POST for all forms handling sensitive data.",
            });
          }
        });
      } catch (e) {
        // Skip pages that fail to load
      }
    }

    return findings;
  },
};
