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
Object.defineProperty(exports, "__esModule", { value: true });
exports.frontendFormsCheck = void 0;
const cheerio = __importStar(require("cheerio"));
exports.frontendFormsCheck = {
    id: "frontend-forms",
    name: "Frontend Forms & Input Security",
    description: "Analyzes HTML forms for missing CSRF tokens, autocomplete on passwords, and exposed data",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // Target HTML pages (non-API routes)
        const htmlPages = discoveredRoutes.filter((r) => r.method === "GET" &&
            !r.path.startsWith("/api/") &&
            !r.path.includes("."));
        for (const route of htmlPages) {
            try {
                const res = await axios.get(route.path, {
                    validateStatus: () => true,
                    headers: { Accept: "text/html" },
                });
                if (res.status !== 200 ||
                    !res.headers["content-type"]?.includes("text/html")) {
                    continue;
                }
                const $ = cheerio.load(res.data);
                // 1. Check forms for CSRF tokens
                $("form").each((_, form) => {
                    const $form = $(form);
                    const action = $form.attr("action") || route.path;
                    const method = ($form.attr("method") || "GET").toUpperCase();
                    // Only check POST/PUT/PATCH forms
                    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method))
                        return;
                    // Look for CSRF token (common names)
                    const hasCSRF = $form.find('input[name*="csrf"], input[name*="token"], input[name="_token"]').length > 0;
                    if (!hasCSRF) {
                        findings.push({
                            id: `missing-csrf-${route.path}-${action}`,
                            checkId: "frontend-forms",
                            category: "frontend",
                            name: "Missing CSRF Token on Form",
                            endpoint: `${route.path} -> ${action}`,
                            risk: "medium",
                            description: `A ${method} form submitting to ${action} has no visible CSRF token field.`,
                            assumption: "Forms are protected by SameSite cookies or developer forgot CSRF entirely.",
                            reproduction: `Visit ${route.path} and inspect the form.`,
                            fix: "Add CSRF tokens to all state-changing forms. Use next-csrf or csurf middleware.",
                        });
                    }
                });
                // 2. Check password fields for autocomplete
                $('input[type="password"]').each((_, input) => {
                    const $input = $(input);
                    const autocomplete = $input.attr("autocomplete");
                    if (!autocomplete ||
                        (autocomplete !== "new-password" &&
                            autocomplete !== "current-password")) {
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
                // 4. Check for client-side validation and test server-side enforcement
                const validationTests = [];
                $("form").each((_, form) => {
                    const $form = $(form);
                    let action = $form.attr("action");
                    const method = ($form.attr("method") || "POST").toUpperCase();
                    // Check if form has onSubmit handler (Next.js, React forms often use JS handlers)
                    const hasOnSubmit = $form.attr("onsubmit") !== undefined;
                    // If no action and no onSubmit, this is likely a JS-handled form
                    if (!action) {
                        // Try to infer from the page context
                        // Login/Register pages typically submit to /api/auth/login or /api/auth/register
                        const pathLower = route.path.toLowerCase();
                        if (pathLower.includes("/login")) {
                            action = "/api/auth/login";
                        }
                        else if (pathLower.includes("/register") ||
                            pathLower.includes("/signup")) {
                            action = "/api/auth/register";
                        }
                        else if (pathLower.includes("/profile")) {
                            action = "/api/user/profile";
                        }
                        else if (pathLower.includes("/settings")) {
                            action = "/api/user/settings";
                        }
                        else {
                            action = route.path; // fallback to same path
                        }
                    } // Default to POST if not specified
                    // Find inputs with validation attributes
                    const validatedInputs = $form.find("input[required], input[pattern], input[min], input[max], input[minlength], input[maxlength], input[type='email'], input[type='url']");
                    if (validatedInputs.length > 0) {
                        // Build invalid payload to test server-side validation
                        const invalidPayload = {};
                        let hasTestableValidation = false;
                        validatedInputs.each((_, input) => {
                            const $input = $(input);
                            const name = $input.attr("name");
                            const type = $input.attr("type") || "text";
                            const required = $input.attr("required") !== undefined;
                            const pattern = $input.attr("pattern");
                            const minLength = $input.attr("minlength");
                            const maxLength = $input.attr("maxlength");
                            if (!name)
                                return;
                            // Generate invalid data based on validation rules
                            if (type === "email") {
                                invalidPayload[name] = "not-an-email";
                                hasTestableValidation = true;
                            }
                            else if (type === "url") {
                                invalidPayload[name] = "not-a-url";
                                hasTestableValidation = true;
                            }
                            else if (pattern) {
                                // Try to violate the pattern (basic heuristic)
                                invalidPayload[name] = "!!!INVALID!!!";
                                hasTestableValidation = true;
                            }
                            else if (minLength) {
                                // Send a string shorter than minlength
                                invalidPayload[name] = "x";
                                hasTestableValidation = true;
                            }
                            else if (maxLength) {
                                // Send a string longer than maxlength
                                const len = parseInt(maxLength) || 100;
                                invalidPayload[name] = "x".repeat(len + 10);
                                hasTestableValidation = true;
                            }
                            else if (required) {
                                // For required fields without specific validation, try empty string
                                if (!invalidPayload[name]) {
                                    invalidPayload[name] = "";
                                    hasTestableValidation = true;
                                }
                            }
                        });
                        // Skip GET method forms (search forms, etc.)
                        if (method === "GET") {
                            if (hasTestableValidation) {
                                findings.push({
                                    id: `client-validation-get-${route.path}`,
                                    checkId: "frontend-forms",
                                    category: "frontend",
                                    name: "Client-Side Validation on GET Form",
                                    endpoint: route.path,
                                    risk: "low",
                                    description: `HTML5 validation on a GET form. GET forms typically shouldn't have strict validation.`,
                                    assumption: "GET forms don't need validation.",
                                    reproduction: `Inspect form on ${route.path}`,
                                    fix: "Use POST for forms that need validation.",
                                });
                            }
                            return; // Skip testing
                        }
                        if (hasTestableValidation &&
                            Object.keys(invalidPayload).length > 0) {
                            // Test the backend asynchronously
                            const testPromise = (async () => {
                                try {
                                    const client = action.startsWith("/api") ? apiAxios : axios;
                                    const res = await client.request({
                                        method,
                                        url: action,
                                        data: invalidPayload,
                                        validateStatus: () => true,
                                    });
                                    // If server accepts invalid data (200/201/204), validation is missing
                                    if (res.status >= 200 && res.status < 300) {
                                        findings.push({
                                            id: `missing-server-validation-${route.path}-${action}`,
                                            checkId: "frontend-forms",
                                            category: "backend",
                                            name: "Missing Server-Side Validation",
                                            endpoint: `${route.path} -> ${method} ${action}`,
                                            risk: "high",
                                            description: `Form on ${route.path} has client-side validation (email, pattern, required, etc.), but the server at ${action} accepted invalid data without rejecting it. Payload: ${JSON.stringify(invalidPayload).substring(0, 100)}...`,
                                            assumption: "Client-side validation is enough; users can't bypass it.",
                                            reproduction: `Send invalid data directly to ${method} ${action} bypassing the browser form validation.`,
                                            fix: "Implement server-side validation matching all frontend rules. Never trust client input.",
                                        });
                                    }
                                    else if (res.status === 400 || res.status === 422) {
                                        // Good! Server rejected invalid data
                                        // No finding needed
                                    }
                                }
                                catch (e) {
                                    // Network error or other issue, skip
                                }
                            })();
                            validationTests.push(testPromise);
                        }
                        else {
                            // Forms exist but can't test automatically (no name attributes, no testable validation patterns, etc.)
                            if (validatedInputs.length > 0) {
                                findings.push({
                                    id: `client-validation-untestable-${route.path}`,
                                    checkId: "frontend-forms",
                                    category: "frontend",
                                    name: "Client-Side Validation Detected (Inputs Missing Names)",
                                    endpoint: route.path,
                                    risk: "low",
                                    description: `HTML5 validation attributes are present but inputs lack 'name' attributes or testable patterns. Found ${validatedInputs.length} validated input(s). Cannot automatically test server-side validation.`,
                                    assumption: "Client-side validation is sufficient.",
                                    reproduction: `Inspect form inputs on ${route.path} - ensure they have proper 'name' attributes for backend processing.`,
                                    fix: "Add 'name' attributes to all form inputs and implement server-side validation.",
                                });
                            }
                        }
                    }
                });
                // Wait for all validation tests to complete
                await Promise.all(validationTests);
                // 5. Check for forms with GET method for sensitive operations
                $('form[method="GET"], form[method="get"]').each((_, form) => {
                    const $form = $(form);
                    const action = $form.attr("action") || route.path;
                    const hasPasswordField = $form.find('input[type="password"]').length > 0;
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
            }
            catch (e) {
                // Skip pages that fail to load
            }
        }
        return findings;
    },
};
