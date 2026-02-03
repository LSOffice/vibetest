# vibetest

🔮 **Localhost-only pentesting CLI for catching vibe-coded vulnerabilities**

A developer-friendly security scanner designed to catch common vulnerabilities in rapidly built (AI-assisted or "vibe-coded") applications.

## Quick Start

```bash
# Install globally
npm start

# Run against your app
vibetest -p 3000

# With separate API backend
vibetest -p 3000 --api-port 8080
```

## 🔐 Authentication

Vibetest automatically discovers credentials from multiple sources (no more manual JWT entry!):

1. **Config file** (`.vibetest.json`) - Recommended
2. **Environment variables** (`VIBETEST_TOKEN`)
3. **Manual entry** (fallback)

### Quick Setup

```bash
# Create a config file
cat > .vibetest.json << EOF
{
  "token": "your-jwt-token-here"
}
EOF

# Add to .gitignore
echo ".vibetest.json" >> .gitignore

# Run test
vibetest -p 3000
```

See [AUTH.md](AUTH.md) for detailed authentication guide.

## Usage

```bash
# Basic scan
vibetest -p 3000

# With authentication from environment
export VIBETEST_TOKEN="your-jwt"
vibetest -p 3000

# Separate frontend/backend ports
vibetest -p 3000 --api-port 8080

# Custom host
vibetest -p 3000 --host 127.0.0.1
```
