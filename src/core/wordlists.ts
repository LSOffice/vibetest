export const DISCOVERY_PATHS = [
  // Roots
  "/",
  "/home",
  "/index.html",
  "/app",
  "/api",
  "/api/v1",
  "/api/v2",
  "/v1",
  "/v2",

  // Swagger / Docs / OpenAPI
  "/api-docs",
  "/docs",
  "/documentation",
  "/swagger",
  "/swagger.json",
  "/swagger.yaml",
  "/openapi.json",
  "/openapi.yaml",
  "/api/openapi.json",
  "/api/openapi.yaml",
  "/api/swagger.json",
  "/api/swagger.yaml",
  "/api/v1/swagger.json",
  "/api/docs",
  "/developers",
  "/developers/docs",

  // GraphQL & Playground
  "/graphql",
  "/api/graphql",
  "/api/v1/graphql",
  "/v1/graphql",
  "/graphiql",
  "/playground",
  "/api/graphiql",
  "/graphql-playground",

  // Auth & Session
  "/auth",
  "/auth/login",
  "/auth/logout",
  "/auth/register",
  "/auth/signup",
  "/auth/forgot-password",
  "/auth/reset-password",
  "/api/auth",
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/register",
  "/api/auth/user",
  "/api/auth/me",
  "/api/login",
  "/api/register",
  "/api/signup",
  "/api/signin",
  "/api/logout",
  "/api/session",
  "/session",
  "/account",
  "/settings/account",
  "/api/user/me",
  "/api/users/current",
  "/api/whoami",
  "/me",

  // Users & Profiles
  "/user",
  "/users",
  "/profile",
  "/profiles",
  "/api/user",
  "/api/users",
  "/api/profile",
  "/api/profiles",
  "/api/me",
  "/api/v1/user",
  "/api/v1/users",
  "/api/v1/me",
  "/api/account",
  "/api/accounts",
  "/api/v1/account",
  "/api/v1/accounts",
  "/user/settings",
  "/user/preferences",

  // Admin & Management
  "/admin",
  "/administrator",
  "/api/admin",
  "/api/administrator",
  "/api/v1/admin",
  "/admin/dashboard",
  "/dashboard",
  "/manage",
  "/manage/users",
  "/manage/settings",
  "/control-panel",
  "/cpanel",
  "/console",
  "/console/login",
  "/admin/login",
  "/adminpanel",
  "/adminarea",
  "/backend",
  "/backend/login",

  // System, Health & Monitoring
  "/health",
  "/healthz",
  "/status",
  "/info",
  "/api/health",
  "/api/healthz",
  "/api/status",
  "/api/info",
  "/actuator",
  "/actuator/health",
  "/metrics",
  "/metrics/prometheus",
  "/prometheus",
  "/prometheus/metrics",
  "/telemetry",
  "/debug",
  "/debug/vars",
  "/debug/pprof",

  // Config, Secrets & Environment
  "/config.json",
  "/api/config",
  "/api/settings",
  "/settings",
  "/.env",
  "/.env.example",
  "/config",
  "/.git",
  "/.git/config",
  "/secrets",
  "/credentials",
  "/.well-known/security.txt",
  "/.well-known/openid-configuration",
  "/.well-known/assetlinks.json",

  // Uploads, Files & Static
  "/upload",
  "/uploads",
  "/api/upload",
  "/api/uploads",
  "/files",
  "/api/files",
  "/assets",
  "/static",
  "/public",
  "/images",
  "/avatars",
  "/download",
  "/downloads",
  "/export",
  "/import",

  // Common Resources / REST endpoints
  "/api/posts",
  "/api/articles",
  "/api/items",
  "/api/products",
  "/api/orders",
  "/api/carts",
  "/api/notifications",
  "/api/messages",
  "/api/search",
  "/api/logs",
  "/api/comments",
  "/api/tags",
  "/api/categories",
  "/api/media",
  "/api/attachments",

  // eCommerce & Payments
  "/checkout",
  "/cart",
  "/billing",
  "/payments",
  "/payment",
  "/api/payments",
  "/api/billing",
  "/api/checkout",
  "/stripe/webhook",
  "/webhooks/stripe",
  "/paypal/ipn",
  "/subscriptions",
  "/invoice",

  // OAuth / SSO
  "/oauth",
  "/oauth/authorize",
  "/oauth/token",
  "/oauth/callback",
  "/auth/oidc",
  "/openid",
  "/openid-configuration",
  "/.well-known/jwks.json",

  // Webhooks & Integrations
  "/webhook",
  "/webhooks",
  "/api/webhooks",
  "/hooks",
  "/integrations",
  "/integrations/github",
  "/integrations/bitbucket",
  "/integrations/slack",

  // CMS, Blog & Static Site paths
  "/blog",
  "/feeds",
  "/rss.xml",
  "/atom.xml",
  "/sitemap.xml",

  // Robots & Sitemap
  "/robots.txt",

  // Common admin tools
  "/phpmyadmin",
  "/pma",
  "/adminer",
  "/sql",
  "/database",
  "/db",
  "/dbadmin",
  "/backup",
  "/backups",

  // CI / CD / Deployment
  "/deploy",
  "/deployment",
  "/ci",
  "/jenkins",
  "/.gitlab-ci.yml",
  "/.github/workflows",

  // Development & Local-only endpoints
  "/dev",
  "/development",
  "/staging",
  "/demo",
  "/test",
  "/qa",
  "/sandbox",
  "/internal",
  "/internal/api",
  "/_internal",

  // Legacy / Common variants
  "/api/v1/auth/login",
  "/api/v1/login",
  "/api/v1/signup",
  "/api/v1/health",
  "/api/v1/status",
  "/api/v1/upload",
  "/v1/auth",
  "/v2/auth",

  // Security & Attack surfaces
  "/.env.backup",
  "/.env.bak",
  "/.htpasswd",
  "/.htaccess",
  "/server-status",
  "/server-info",

  // Logs & Diagnostics
  "/logs",
  "/api/logs",
  "/system/logs",
  "/error",
  "/errors",

  // Support & Help
  "/help",
  "/support",
  "/contact",
  "/feedback",
  "/faq",

  // Account lifecycle & billing
  "/signup/complete",
  "/signup/verify",
  "/verify-email",
  "/resend-verification",
  "/subscription/cancel",

  // Files and exports
  "/export/csv",
  "/export/json",
  "/download/csv",

  // Admin API variations
  "/api/admin/users",
  "/api/admin/settings",
  "/api/v1/admin/users",
  "/api/v1/admin/settings",

  // Third-party endpoints (common names)
  "/sso",
  "/signin/oauth",
  "/callback/oauth",
  "/auth/github",
  "/auth/google",
  "/auth/facebook",

  // Feature-specific endpoints
  "/search",
  "/api/search",
  "/suggest",
  "/autocomplete",
  "/suggestions",

  // Messaging, Real-time & sockets
  "/ws",
  "/socket.io",
  "/realtime",
  "/notifications",

  // Rate-limit & abuse
  "/rate-limit",
  "/throttle",

  // Policies & legal
  "/terms",
  "/privacy",
  "/cookies",

  // Installer and setup
  "/install",
  "/setup",
  "/onboarding",
  "/initial-setup",

  // Misc useful probes
  "/favicon.ico",
  "/humans.txt",
  "/crossdomain.xml",

  // Misc hidden or interesting files
  "/.gitignore",
  "/LICENSE",
  "/README.md",

  // API pagination and common params endpoints
  "/api/items?page=1",
  "/api/items?page=2",

  // Admin CLI and tooling
  "/ops",
  "/ops/status",
  "/ops/maintenance",

  // Additional monitoring & observability
  "/sentry",
  "/sentry/health",
  "/newrelic",

  // Extra common paths used by frameworks
  "/_next/static",
  "/__next__",
  "/next",

  // Common CMS endpoints
  "/wp-admin",
  "/wp-login.php",
  "/wp-content",
  "/wp-json",

  // API versioning permutations
  "/api/v3",
  "/api/v3/users",
  "/services",
  "/service",

  // Misc endpoints often exposed by misconfigured apps
  "/.env.local",
  "/.env.production",
  "/config.php",
  "/phpinfo.php",

  // Utility endpoints
  "/ping",
  "/isalive",
  "/ready",

  // Fallback catch-alls and patterns
  "/hidden",
  "/secret",
  "/secrets",
  "/private",
  "/internal-only",

  // More API resource patterns
  "/api/v1/orders",
  "/api/v1/products",
  "/api/v2/orders",
  "/api/v2/products",

  // Extended admin and tools
  "/admin/tools",
  "/admin/maintenance",

  // Additional well-known resources
  "/.well-known/security.txt",
  "/.well-known/change-password",

  // Development convenience
  "/__health__",
  "/__status__",

  // System endpoints occasionally exposed
  "/proc",
  "/sys",

  // Extra static/name variations to increase coverage
  "/api2",
  "/api3",
  "/v3",
  "/v4",

  // Catch common typos
  "/admim",
  "/admn",
  "/logn",

  // Common developer endpoints
  "/swagger-ui",
  "/swagger-ui.html",
  "/redoc",

  // End of list (expanded)
];
