"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.inputValidationCheck = void 0;
const INJECTION_PAYLOADS = [
    { name: 'Proto Pollution', data: { "__proto__": { "vulnerable": true } } },
    { name: 'Type Confusion (Null)', data: { "email": null, "username": null, "id": null } },
    { name: 'Type Confusion (Array)', data: { "password": ["password"] } }, // Express body-parser vulnerability
    { name: 'Type Confusion (Boolean)', data: { "isAdmin": "true" } },
];
exports.inputValidationCheck = {
    id: 'input-validation',
    name: 'Input Validation & Type Confusion',
    description: 'Checks if API catches wrong types, nulls, and prototype pollution',
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // Only target methods likely to accept body
        const candidates = discoveredRoutes.filter(r => ['POST', 'PUT', 'PATCH'].includes(r.method));
        for (const route of candidates) {
            for (const payload of INJECTION_PAYLOADS) {
                try {
                    const client = route.path.startsWith('/api') ? apiAxios : axios;
                    const res = await client.request({
                        method: route.method,
                        url: route.path,
                        data: payload.data,
                        validateStatus: () => true
                    });
                    // Analysis
                    // 1. Crash? (500)
                    if (res.status === 500) {
                        findings.push({
                            id: `crash-${payload.name}-${route.path}`,
                            checkId: 'input-validation',
                            category: 'backend',
                            name: `Application Crash via ${payload.name}`,
                            endpoint: route.method + ' ' + route.path,
                            risk: 'medium',
                            description: `Sending ${JSON.stringify(payload.data)} caused a 500 Internal Server Error.`,
                            assumption: 'Input is strictly typed and validated before use.',
                            reproduction: `Send payload to ${route.path}`,
                            fix: 'Use schema validation (Zod, Yup, Joi) to strictly reject invalid types.'
                        });
                    }
                    // 2. Prototype Pollution check (if reflection)
                    if (payload.name === 'Proto Pollution' && res.status < 400) {
                        const bodyStr = JSON.stringify(res.data);
                        // Very crude check: does it reflect 'vulnerable'?
                        // Or headers?
                        if (bodyStr.includes('vulnerable')) {
                            findings.push({
                                id: `proto-reflection-${route.path}`,
                                checkId: 'input-validation',
                                category: 'backend',
                                name: 'Potential Prototype Pollution Reflection',
                                endpoint: route.path,
                                risk: 'high',
                                description: `The server reflected the injected __proto__ property, suggesting it might have merged it into the object.`,
                                assumption: 'Deep merge functions are safe.',
                                reproduction: `Send __proto__ payload to ${route.path}`,
                                fix: 'Use `Object.create(null)` or safe merge libraries.'
                            });
                        }
                    }
                    // 3. Array bypass check (if status 200/201 on password field)
                    if (payload.name === 'Type Confusion (Array)' &&
                        (route.path.includes('login') || route.path.includes('auth')) &&
                        res.status === 200) {
                        findings.push({
                            id: `array-bypass-${route.path}`,
                            checkId: 'input-validation',
                            category: 'backend',
                            name: 'Parameter Type Confusion (Array Bypass)',
                            endpoint: route.path,
                            risk: 'high',
                            description: `Accepted an array for a password field. In some old libraries, this bypassed string checks.`,
                            assumption: 'Password is always a string.',
                            reproduction: `Send password as ["password"]`,
                            fix: 'Enforce string type strictly.'
                        });
                    }
                }
                catch (e) { /* ignore */ }
            }
        }
        return findings;
    }
};
