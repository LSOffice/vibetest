import puppeteer from "puppeteer";
import axios from "axios";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";
import { getRateLimitInstance } from "../core/rate-limit.js";

/**
 * Frontend Validation Bypass Check (Enhanced)
 *
 * Extracts validation rules from frontend code and tests if backend enforces them:
 * - Length limits (minLength, maxLength)
 * - Regex patterns
 * - Required fields
 * - Data type constraints
 */
export async function checkValidationBypass(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n📝 Testing Frontend Validation Bypass..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    // Navigate to find forms
    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Extract validation rules from JS bundles
    const validationRules = await page.evaluate(() => {
      const rules: {
        field: string;
        minLength?: number;
        maxLength?: number;
        pattern?: string;
        required?: boolean;
        type?: string;
      }[] = [];

      // Check form elements
      const inputs = document.querySelectorAll("input, textarea");
      inputs.forEach((input) => {
        const el = input as HTMLInputElement;
        const rule: any = {
          field: el.name || el.id || "unknown",
        };

        if (el.minLength) rule.minLength = el.minLength;
        if (el.maxLength) rule.maxLength = el.maxLength;
        if (el.pattern) rule.pattern = el.pattern;
        if (el.required) rule.required = true;
        if (el.type) rule.type = el.type;

        if (rule.minLength || rule.maxLength || rule.pattern || rule.required) {
          rules.push(rule);
        }
      });

      return rules;
    });

    // Also scan JavaScript for Zod/Yup schemas
    const scripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll("script"))
        .map((s) => s.textContent)
        .join("\n");
    });

    // Look for validation patterns in JS
    const zodPatterns = [
      /z\.string\(\)\.min\((\d+)\)/g,
      /z\.string\(\)\.max\((\d+)\)/g,
      /z\.string\(\)\.email\(\)/g,
      /z\.string\(\)\.url\(\)/g,
      /\.required\(\)/g,
    ];

    const yupPatterns = [
      /yup\.string\(\)\.min\((\d+)\)/g,
      /yup\.string\(\)\.max\((\d+)\)/g,
      /yup\.string\(\)\.email\(\)/g,
      /\.required\(\)/g,
    ];

    let foundClientValidation = false;
    for (const pattern of [...zodPatterns, ...yupPatterns]) {
      if (pattern.test(scripts)) {
        foundClientValidation = true;
        break;
      }
    }

    if (foundClientValidation) {
      findings.push({
        id: "validation-library-detected",
        checkId: "validation-bypass",
        category: "frontend",
        name: "Client-Side Validation Library Detected",
        description:
          "Found Zod/Yup validation in client bundles. Testing if backend enforces these rules...",
        endpoint: config.baseUrl,
        risk: "low",
        assumption:
          "Backend validates all input independently of frontend validation",
        reproduction:
          "Inspect JavaScript bundles for Zod/Yup validation schemas",
        fix: "Ensure backend validates all input independently of frontend validation.",
      });
    }

    await browser.close();

    // Now test backend with invalid data
    const axiosInstance = getRateLimitInstance(config);
    const postRoutes = routes.filter(
      (r) => r.method === "POST" || r.method === "PUT" || r.method === "PATCH",
    );

    for (const route of postRoutes) {
      // Test cases that should fail frontend validation
      const testCases = [
        { name: "Empty required fields", data: {} },
        {
          name: "Excessively long strings",
          data: {
            name: "A".repeat(10000),
            email: "test@" + "a".repeat(500) + ".com",
            description: "X".repeat(100000),
          },
        },
        {
          name: "Invalid email formats",
          data: {
            email: "notanemail",
            username: "../../../etc/passwd",
          },
        },
        {
          name: "Negative numbers",
          data: {
            age: -99,
            quantity: -1,
            price: -999,
          },
        },
        {
          name: "SQL/Script injection attempts",
          data: {
            name: "'; DROP TABLE users--",
            comment: "<script>alert(1)</script>",
          },
        },
      ];

      for (const testCase of testCases) {
        try {
          logTestAttempt({
            check: "validation-bypass",
            endpoint: `${route.method} ${route.path}`,
            status: "TESTING",
            details: testCase.name,
          });

          const response = await axiosInstance.request({
            method: route.method,
            url: route.path,
            data: testCase.data,
            validateStatus: () => true,
          });

          // If server accepts invalid data
          if (response.status >= 200 && response.status < 300) {
            findings.push({
              id: `validation-bypass-${route.path.replace(/\//g, "-")}-${testCase.name.replace(/\s/g, "-")}`,
              checkId: "validation-bypass",
              category: "backend",
              name: `Backend Accepts Invalid Data: ${testCase.name}`,
              description: `Server accepted ${testCase.name} without proper validation. Frontend validation can be bypassed.`,
              endpoint: `${route.method} ${route.path}`,
              risk: "high",
              assumption: "Backend validates input according to frontend rules",
              reproduction: `Send ${testCase.name} to ${route.method} ${route.path}`,
              fix: "Implement server-side validation that matches or exceeds frontend validation rules. Use Zod/Yup on the backend too.",
            });

            logTestAttempt({
              check: "validation-bypass",
              endpoint: `${route.method} ${route.path}`,
              status: "VULNERABLE",
              details: `Accepted: ${testCase.name}`,
            });
          } else if (response.status === 400 || response.status === 422) {
            // Good - server is validating
            logTestAttempt({
              check: "validation-bypass",
              endpoint: `${route.method} ${route.path}`,
              status: "SECURE",
              details: `Rejected: ${testCase.name}`,
            });
          }
        } catch (error: any) {
          // Errors are fine - means server rejected it
        }
      }
    }
  } catch (error) {
    console.log(chalk.yellow("  ⚠ Could not complete validation bypass check"));
  }

  return findings;
}
