import axios from "axios";
import { VibeConfig } from "./types.js";

/**
 * Creates an axios instance with rate limiting
 */
export function getRateLimitInstance(config: VibeConfig) {
  return axios.create({
    baseURL: config.baseUrl,
    timeout: 10000,
  });
}
