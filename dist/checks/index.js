"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checks = void 0;
const auth_presence_js_1 = require("./auth-presence.js");
const idor_js_1 = require("./idor.js");
const mass_assignment_js_1 = require("./mass-assignment.js");
const security_headers_js_1 = require("./security-headers.js");
const unsafe_methods_js_1 = require("./unsafe-methods.js");
const graphql_js_1 = require("./graphql.js");
const security_by_comment_js_1 = require("./security-by-comment.js");
const race_condition_js_1 = require("./race-condition.js");
const error_handling_js_1 = require("./error-handling.js");
const input_validation_js_1 = require("./input-validation.js");
const cookies_js_1 = require("./cookies.js");
const rate_limit_js_1 = require("./rate-limit.js");
const frontend_forms_js_1 = require("./frontend-forms.js");
const client_secrets_js_1 = require("./client-secrets.js");
exports.checks = [
    auth_presence_js_1.authPresenceCheck,
    idor_js_1.idorCheck,
    mass_assignment_js_1.massAssignmentCheck,
    security_headers_js_1.securityHeadersCheck,
    unsafe_methods_js_1.unsafeMethodsCheck,
    graphql_js_1.graphqlCheck,
    security_by_comment_js_1.securityByCommentCheck,
    race_condition_js_1.raceConditionCheck,
    error_handling_js_1.errorHandlingCheck,
    input_validation_js_1.inputValidationCheck,
    cookies_js_1.cookieSecurityCheck,
    rate_limit_js_1.rateLimitCheck,
    frontend_forms_js_1.frontendFormsCheck,
    client_secrets_js_1.clientSideSecretsCheck,
];
