# Vibetest Authentication Guide

Vibetest supports multiple ways to authenticate with your application. No more manual JWT entry every time!

## 🔐 Authentication Methods (Priority Order)

### 1. **Config File (Recommended)** `.vibetest.json`

Create a `.vibetest.json` file in your project root:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "cookies": {
    "session": "your-session-cookie-here",
    "auth_token": "your-auth-token-here"
  },
  "headers": {
    "X-API-Key": "your-api-key-here"
  }
}
```

**Benefits:**

- ✅ Persistent across runs
- ✅ Easy to update
- ✅ Supports tokens, cookies, and custom headers
- ⚠️ Add to `.gitignore` to avoid committing secrets!

### 2. **Environment Variables**

Set one of these environment variables:

```bash
export VIBETEST_TOKEN="your-jwt-token"
# or
export JWT_TOKEN="your-jwt-token"
# or
export AUTH_TOKEN="your-jwt-token"
```

Then run:

```bash
vibetest -p 3000
```

**Benefits:**

- ✅ Great for CI/CD pipelines
- ✅ No files to manage
- ✅ Secure (not committed to git)

### 3. **Automatic Browser Capture** 🆕

Let Vibetest open a browser and capture your login automatically! When prompted, select "Automatic (Open Browser & Login)":

```bash
? How would you like to authenticate?
  ❯ 🌐 Automatic (Open Browser & Login)
    🔑 Enter Bearer Token (JWT)
    💾 Save config for future (.vibetest.json)
    ⏭️  Skip for now
```

**How it works:**

1. Opens Chrome/Chromium browser to your login page
2. You login normally (username/password, OAuth, etc.)
3. Vibetest monitors network traffic and captures:
   - Authorization headers (Bearer tokens)
   - JWT tokens in responses
   - Session cookies
   - Auth tokens in localStorage
4. Optionally saves credentials to `.vibetest.json` for future use

**Benefits:**

- ✅ No manual token copying
- ✅ Works with any auth method (OAuth, SAML, custom)
- ✅ Captures all auth data automatically
- ✅ Visual confirmation of successful login

**What gets captured:**

- **Authorization headers**: `Bearer eyJhbGci...`
- **JWT responses**: Any `eyJ...` pattern in response bodies
- **localStorage**: Keys containing 'token', 'auth', 'jwt'
- **Cookies**: Session cookies, auth tokens

### 4. **Manual Entry** (Fallback)

If no automatic auth is found, Vibetest will prompt you:

```
? No auth credentials found. Do you want to authenticate now? (Y/n)
? How would you like to authenticate?
  ❯ Enter Bearer Token (JWT)
    Save config for future (.vibetest.json)
    Skip for now
```

## 📖 Usage Examples

### Example 1: Automatic Browser Capture (Easiest!) 🆕

```bash
vibetest -p 3000
# When prompted, select "Automatic (Open Browser & Login)"
# Browser opens → Login normally → Credentials captured automatically!
```

Output:

```
? No auth credentials found. Do you want to authenticate now? Yes
? How would you like to authenticate? 🌐 Automatic (Open Browser & Login)

🌐 Opening browser for login...
  → Navigating to http://localhost:3000/login
  → Waiting for authentication (timeout: 2 minutes)...
  ✓ Found Authorization header: Bearer eyJhbGci...
  ✓ Found session cookie: session_id
  ✓ Authentication configured from browser.
? Save these credentials to .vibetest.json for future use? Yes
  ✓ Saved to .vibetest.json
```

### Example 2: Using Config File

```bash
# Create config
cat > .vibetest.json << EOF
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMifQ.abc123"
}
EOF

# Add to .gitignore
echo ".vibetest.json" >> .gitignore

# Run test
vibetest -p 3000
```

Output:

```
🔍 Looking for authentication credentials...
✓ Found credentials in .vibetest.json
```

### Example 3: Using Environment Variable

```bash
export VIBETEST_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
vibetest -p 3000
```

### Example 4: Manual JWT Extraction (Old Way)

1. Open your app in browser
2. Login normally
3. Open DevTools (F12)
4. Go to Application/Storage → Cookies or Local Storage
5. Copy the JWT token
6. Save to `.vibetest.json` or enter when prompted

**Note:** Browser capture (Example 1) automates steps 3-6!

## 🛡️ Security Best Practices

1. **Always add `.vibetest.json` to `.gitignore`**
2. Use environment variables in CI/CD
3. Use short-lived tokens
4. Rotate tokens regularly
5. Never commit tokens to version control

## 🎯 Pro Tips

- **Use separate test accounts** with limited permissions
- **Refresh tokens before long test runs** to avoid expiration
- **Test both authenticated and unauthenticated scenarios** by running twice
