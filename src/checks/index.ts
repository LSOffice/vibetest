import { Check } from "../core/types.js";
import { authPresenceCheck } from "./auth-presence.js";
import { jwtSecurityCheck } from "./jwt-security.js";
import { idorCheck } from "./idor.js";
import { massAssignmentCheck } from "./mass-assignment.js";
import { securityHeadersCheck } from "./security-headers.js";
import { unsafeMethodsCheck } from "./unsafe-methods.js";
import { graphqlCheck } from "./graphql.js";
import { securityByCommentCheck } from "./security-by-comment.js";
import { raceConditionCheck } from "./race-condition.js";
import { errorHandlingCheck } from "./error-handling.js";
import { inputValidationCheck } from "./input-validation.js";
import { cookieSecurityCheck } from "./cookies.js";
import { rateLimitCheck } from "./rate-limit.js";
import { frontendFormsCheck } from "./frontend-forms.js";
import { clientSideSecretsCheck } from "./client-secrets.js";

// Injection attacks (critical priority)
import { sqlInjectionCheck } from "./sql-injection.js";
import { nosqlInjectionCheck } from "./nosql-injection.js";
import { commandInjectionCheck } from "./command-injection.js";
import { xssInjectionCheck } from "./xss-injection.js";

// Client-side security
import { checkUnsafeRendering } from "./unsafe-rendering.js";
import { checkClientSideAuthorization } from "./client-authorization.js";
import { checkClientDataTrust } from "./client-data-trust.js";

// Auth flow
import { checkAuthRedirects } from "./auth-redirects.js";
import { corsCredentialsCheck } from "./cors-credentials.js";

// Validation
import { checkValidationBypass } from "./validation-bypass.js";

// Storage & routing
import { checkStorageTrust } from "./storage-trust.js";
import { checkSSRLeaks } from "./ssr-leaks.js";
import { checkClientRouting } from "./client-routing.js";

// Wrapper for function-based checks that need Check interface
const unsafeRenderingCheck: Check = {
  id: "unsafe-rendering",
  name: "Unsafe Rendering Patterns",
  description: "Detects XSS-prone patterns like dangerouslySetInnerHTML, v-html, eval()",
  async run({ config, discoveredRoutes }) {
    return await checkUnsafeRendering(config, discoveredRoutes);
  },
};

const clientAuthorizationCheck: Check = {
  id: "client-authorization",
  name: "Client-Side Authorization Trust",
  description: "Tests if UI hides admin/privileged actions but API allows them",
  async run({ config, discoveredRoutes }) {
    return await checkClientSideAuthorization(config, discoveredRoutes);
  },
};

const clientDataTrustCheck: Check = {
  id: "client-data-trust",
  name: "API Trust in Client-Generated Data",
  description: "Tests if backend trusts client-calculated values like prices, totals, status flags",
  async run({ config, discoveredRoutes }) {
    return await checkClientDataTrust(config, discoveredRoutes);
  },
};

const authRedirectsCheck: Check = {
  id: "auth-redirects",
  name: "OAuth/Auth Redirect Handling",
  description: "Tests for unvalidated redirects in auth flows (open redirect)",
  async run({ config, discoveredRoutes }) {
    return await checkAuthRedirects(config, discoveredRoutes);
  },
};

const validationBypassCheck: Check = {
  id: "validation-bypass",
  name: "Frontend Validation Bypass",
  description: "Tests if backend enforces frontend validation rules",
  async run({ config, discoveredRoutes }) {
    return await checkValidationBypass(config, discoveredRoutes);
  },
};

const storageTrustCheck: Check = {
  id: "storage-trust",
  name: "localStorage/sessionStorage Trust",
  description: "Tests if server trusts client storage for auth state, roles, permissions",
  async run({ config, discoveredRoutes }) {
    return await checkStorageTrust(config, discoveredRoutes);
  },
};

const ssrLeaksCheck: Check = {
  id: "ssr-leaks",
  name: "SSR Boundary Leaks",
  description: "Tests for server-side data leaked to client in Next.js/Nuxt __NEXT_DATA__ / __NUXT__",
  async run({ config, discoveredRoutes }) {
    return await checkSSRLeaks(config, discoveredRoutes);
  },
};

const clientRoutingCheck: Check = {
  id: "client-routing",
  name: "Client-Side Routing & Route Guards",
  description: "Tests if route protection is only client-side and can be bypassed",
  async run({ config, discoveredRoutes }) {
    return await checkClientRouting(config, discoveredRoutes);
  },
};

// Prioritized check registry: critical vulnerabilities first
export const checks: Check[] = [
  // Critical: Injection attacks
  sqlInjectionCheck,
  nosqlInjectionCheck,
  commandInjectionCheck,
  xssInjectionCheck,
  unsafeRenderingCheck,

  // High: Auth & authorization
  authPresenceCheck,
  jwtSecurityCheck,
  authRedirectsCheck,
  clientAuthorizationCheck,
  corsCredentialsCheck,

  // High: Validation & trust
  validationBypassCheck,
  massAssignmentCheck,
  idorCheck,

  // Medium: Config & headers
  securityHeadersCheck,
  cookieSecurityCheck,

  // Medium: API security
  graphqlCheck,
  unsafeMethodsCheck,
  rateLimitCheck,

  // Medium: Client-side security
  clientSideSecretsCheck,
  storageTrustCheck,
  clientDataTrustCheck,
  ssrLeaksCheck,
  clientRoutingCheck,

  // Low: Logic & detection
  raceConditionCheck,
  errorHandlingCheck,
  inputValidationCheck,
  securityByCommentCheck,
  frontendFormsCheck,
];
