export interface VibeConfig {
  baseUrl: string; // Frontend URL
  apiUrl?: string; // Backend API URL (if different from frontend)
  port: number;
  apiPort?: number; // Backend port (if different)
  auth?: {
    username?: string;
    password?: string;
    token?: string;
    cookies?: Record<string, string>;
    headers?: Record<string, string>;
  };
  safeMode: boolean; // No destructive tests
}

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type FindingCategory = "frontend" | "backend" | "config" | "logic";

export interface Finding {
  id: string;
  checkId: string;
  category?: FindingCategory;
  name: string;
  endpoint: string;
  risk: RiskLevel;
  description: string;
  assumption: string; // The "vibe" assumption that was broken
  reproduction: string;
  fix: string;
}

export interface CheckContext {
  config: VibeConfig;
  axios: any; // Frontend axios instance
  apiAxios: any; // Backend API axios instance (may be same as axios)
  discoveredRoutes: Route[];
}

export interface Check {
  id: string;
  name: string;
  description: string;
  run: (context: CheckContext) => Promise<Finding[]>;
}

export interface Route {
  path: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  inputs?: Record<string, any>;
  authRequired?: boolean;
}
