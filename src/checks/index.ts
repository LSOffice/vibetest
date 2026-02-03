import { Check } from "../core/types.js";
import { authPresenceCheck } from "./auth-presence.js";
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

export const checks: Check[] = [
  authPresenceCheck,
  idorCheck,
  massAssignmentCheck,
  securityHeadersCheck,
  unsafeMethodsCheck,
  graphqlCheck,
  securityByCommentCheck,
  raceConditionCheck,
  errorHandlingCheck,
  inputValidationCheck,
  cookieSecurityCheck,
  rateLimitCheck,
  frontendFormsCheck,
  clientSideSecretsCheck,
];
