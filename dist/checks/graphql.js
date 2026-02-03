"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.graphqlCheck = void 0;
exports.graphqlCheck = {
    id: "graphql-introspection",
    name: "GraphQL Introspection",
    description: "Checks if GraphQL Introspection is enabled",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // Check if we found graphql
        const graphqlRoute = discoveredRoutes.find((r) => r.path === "/graphql") || { path: "/graphql" };
        try {
            const query = {
                query: `
            query {
                __schema {
                    types {
                        name
                    }
                }
            }
            `,
            };
            const res = await apiAxios.post(graphqlRoute.path, query, {
                validateStatus: () => true,
            });
            if (res.status === 200 && res.data?.data?.__schema) {
                findings.push({
                    id: "graphql-introspection-enabled",
                    checkId: "graphql-introspection",
                    category: "config",
                    name: "GraphQL Introspection Enabled",
                    endpoint: graphqlRoute.path,
                    risk: "low",
                    description: `The GraphQL schema is fully queryable via introspection.`,
                    assumption: "It is fine to expose the full data graph schema to the public.",
                    reproduction: `Send a POST to ${graphqlRoute.path} with { query: "{ __schema { types { name } } }" }`,
                    fix: "Disable introspection in production (e.g. `introspection: false` in Apollo).",
                });
            }
        }
        catch (e) {
            // Not graphql or not accessible
        }
        return findings;
    },
};
