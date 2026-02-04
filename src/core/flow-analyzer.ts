/**
 * Flow Analyzer - Integration & E2E Bug Hunting
 *
 * This is what makes whiterose 10x better than pattern matching.
 *
 * Unit analysis asks: "Is there a bug in this function?"
 * Flow analysis asks: "Can an attacker actually exploit this?"
 *
 * Three levels of analysis:
 * 1. DATA FLOW - Trace user input from entry to sink
 * 2. CONTROL FLOW - Trace auth/validation through the call chain
 * 3. ATTACK CHAINS - Find combinations that create real exploits
 */

import { Bug, BugCategory, CodebaseUnderstanding } from '../types.js';

// ─────────────────────────────────────────────────────────────
// Flow Analysis Pass Definitions
// ─────────────────────────────────────────────────────────────

export interface FlowPassConfig {
  name: string;
  level: 'integration' | 'e2e';
  description: string;
  entryPointPatterns: string[];
  traceInstructions: string;
  whatToFind: string[];
  exampleVulnerability: string;
}

export const FLOW_PASSES: FlowPassConfig[] = [
  // ───────────────────────────────────────────────────────────
  // INTEGRATION PASSES - Trace across components
  // ───────────────────────────────────────────────────────────
  {
    name: 'auth-flow-trace',
    level: 'integration',
    description: 'Trace authentication from middleware to every protected route',
    entryPointPatterns: [
      'auth middleware files',
      'JWT verification functions',
      'session validation',
      'route definitions with auth requirements',
    ],
    traceInstructions: `1. Find all auth middleware (isAuthenticated, requireAuth, verifyToken, etc.)
2. Map which routes use this middleware
3. For EACH route that should be protected:
   - Verify the middleware is actually applied
   - Check the middleware can't be bypassed (early returns, error handling)
   - Verify the middleware result is actually used (not just called)
4. Find routes that SHOULD be protected but AREN'T
5. Find routes where auth check happens but result is ignored`,
    whatToFind: [
      'Routes missing auth middleware that access user data',
      'Auth middleware that catches errors and continues',
      'Auth check result not used (called but ignored)',
      'Auth bypass via parameter pollution or type confusion',
      'Different auth levels not enforced (user vs admin)',
    ],
    exampleVulnerability: `// Auth middleware exists but not applied to sensitive route
router.get('/users', authMiddleware, listUsers);  // Protected
router.delete('/users/:id', deleteUser);          // UNPROTECTED - missing authMiddleware!

// Or: Auth check that fails open
async function authMiddleware(req, res, next) {
  try {
    req.user = verifyToken(req.headers.auth);
  } catch (e) {
    // BUG: Continues even on auth failure!
  }
  next();
}`,
  },
  {
    name: 'data-flow-trace',
    level: 'integration',
    description: 'Trace user input from HTTP entry to dangerous sinks',
    entryPointPatterns: [
      'req.body, req.query, req.params',
      'request.json(), request.form()',
      'event.body (Lambda)',
      'ctx.request.body (Koa)',
    ],
    traceInstructions: `1. Find all HTTP entry points (routes, handlers, controllers)
2. Identify where user input enters (req.body, req.query, etc.)
3. TRACE each input through the code:
   - Follow variable assignments
   - Follow function calls (input passed as argument)
   - Follow returns (input returned and used by caller)
   - Follow object properties (input stored in object, object passed around)
4. Track what transformations happen (validation? sanitization? encoding?)
5. Find where the input reaches a SINK:
   - Database queries (SQL, NoSQL)
   - Command execution (exec, spawn)
   - File operations (readFile, writeFile)
   - HTML rendering (innerHTML, template)
   - URL construction (fetch, redirect)
6. Verify transformations between entry and sink actually prevent exploitation`,
    whatToFind: [
      'Input reaches SQL query without parameterization',
      'Input reaches exec/spawn without sanitization',
      'Input reaches file path without path traversal check',
      'Input reaches HTML without encoding',
      'Input validated at controller but re-fetched raw at service layer',
      'Validation exists but can be bypassed via type coercion',
    ],
    exampleVulnerability: `// Controller validates, but service re-reads raw input
// CONTROLLER
async function updateUser(req, res) {
  const { name } = validateInput(req.body);  // Validated!
  await userService.update(req.params.id, req.body);  // BUG: Passes raw req.body!
}

// SERVICE
async function update(id, data) {
  await db.query(\`UPDATE users SET name = '\${data.name}' WHERE id = \${id}\`);
  // data.name is RAW - validation was bypassed!
}`,
  },
  {
    name: 'validation-boundary-trace',
    level: 'integration',
    description: 'Trace validation across layer boundaries',
    entryPointPatterns: [
      'Zod/Joi/Yup schema definitions',
      'validate() function calls',
      'Type assertions after parse',
      'Controller input handling',
    ],
    traceInstructions: `1. Find all validation points (Zod schemas, Joi, manual validation)
2. For each validation:
   - What does it validate? (type, format, range, etc.)
   - Where is it applied? (controller, service, repository)
3. Trace data AFTER validation:
   - Is the validated data used, or is raw data re-read?
   - Can downstream code receive unvalidated data via another path?
   - Are there type assertions that assume validation happened?
4. Find GAPS:
   - Data enters via path A (validated) and path B (not validated)
   - Validation at edge, but internal services trust any input
   - Partial validation (checks type but not format/range)`,
    whatToFind: [
      'Raw data used after validation point (validation bypassed)',
      'Internal APIs callable without going through validated entry point',
      'Type assertion assumes validation that may not have happened',
      'Validation schema is incomplete (missing fields attackers can inject)',
      'Validation at HTTP layer but WebSocket bypasses it',
    ],
    exampleVulnerability: `// Validation exists but internal API bypasses it
// PUBLIC API - Validated
app.post('/api/users', validateBody(userSchema), createUser);

// INTERNAL API - No validation!
app.post('/internal/users', createUser);  // Same handler, no validation

// Or: GraphQL resolver bypasses REST validation
// REST is validated, but GraphQL calls same service without validation`,
  },
  {
    name: 'error-propagation-trace',
    level: 'integration',
    description: 'Trace how errors bubble up and where they leak or fail open',
    entryPointPatterns: [
      'try/catch blocks',
      'Promise .catch() handlers',
      'Error middleware',
      'Global error handlers',
    ],
    traceInstructions: `1. Find all error handling points (try/catch, .catch, error middleware)
2. For each error handler:
   - What errors does it catch?
   - What does it do? (log, return, rethrow, ignore)
   - Does it expose sensitive info? (stack traces, SQL errors, internal paths)
3. Trace error propagation:
   - If function A throws, does caller B handle it?
   - If B doesn't handle, does it propagate to user?
4. Find DANGEROUS patterns:
   - catch {} (empty catch - swallows error, continues)
   - catch { log(error) } (logs but continues as if success)
   - catch { return null } (fails silent, caller doesn't know)
   - Error message includes internal details`,
    whatToFind: [
      'Empty catch blocks that swallow errors',
      'Auth errors caught and converted to success',
      'Database errors exposed to user (leaks schema info)',
      'Stack traces returned in production',
      'Error handling differs between environments (dev vs prod)',
    ],
    exampleVulnerability: `// Auth check fails open on error
async function requireAdmin(req, res, next) {
  try {
    const user = await getUser(req.userId);
    if (user.role !== 'admin') return res.status(403).send('Forbidden');
  } catch (error) {
    console.error(error);
    // BUG: No return! Falls through to next() on error
  }
  next();
}

// Or: Error leaks internal info
catch (error) {
  res.status(500).json({
    error: error.message,  // "ECONNREFUSED 10.0.0.5:5432" - leaks internal IP!
    stack: error.stack     // Full stack trace with file paths
  });
}`,
  },
  {
    name: 'trust-boundary-trace',
    level: 'integration',
    description: 'Find where trusted and untrusted data cross boundaries',
    entryPointPatterns: [
      'External API calls (fetch, axios)',
      'Database reads (might contain user-injected data)',
      'File reads (config, uploads)',
      'Message queues (events from other services)',
    ],
    traceInstructions: `1. Map TRUST BOUNDARIES:
   - User input (always untrusted)
   - Database data (may contain user-injected content)
   - External API responses (untrusted)
   - Config files (trusted if not user-editable)
   - Environment variables (trusted)
2. Find where untrusted data BECOMES trusted:
   - Database read assumed to be safe (but contains user content)
   - External API response used without validation
   - Uploaded file content used directly
3. Find IMPLICIT TRUST:
   - "This came from our database so it's safe" (wrong!)
   - "This is from our other microservice so it's trusted" (wrong!)
   - "The user is authenticated so their input is safe" (wrong!)`,
    whatToFind: [
      'Database content used in SQL query (stored XSS becomes SQLi)',
      'External API response used in template (SSRF + XSS chain)',
      'Uploaded file content executed or included',
      'Inter-service communication without validation',
      'User-controlled config file paths',
    ],
    exampleVulnerability: `// Data from database treated as trusted
async function renderProfile(userId) {
  const user = await db.users.findById(userId);
  // user.bio was set by the user - contains untrusted content!
  return \`<div>\${user.bio}</div>\`;  // STORED XSS - bio contains <script>
}

// Or: External API response trusted
const data = await fetch('https://partner-api.com/data').then(r => r.json());
await db.query(\`INSERT INTO cache VALUES ('\${data.value}')\`);  // SQLi via partner API!`,
  },

  // ───────────────────────────────────────────────────────────
  // E2E PASSES - Full attack scenarios
  // ───────────────────────────────────────────────────────────
  {
    name: 'attack-chain-analysis',
    level: 'e2e',
    description: 'Find combinations of issues that create exploitable attack chains',
    entryPointPatterns: [
      'All previously found vulnerabilities',
      'Low-severity issues that combine into high-severity',
      'Information disclosure + action endpoints',
    ],
    traceInstructions: `1. Review all findings (including low-severity)
2. Look for CHAINS:
   - Info disclosure → targeted attack (leak user IDs → IDOR)
   - XSS → session theft → account takeover
   - SSRF → internal service access → data exfiltration
   - SQLi read → credential theft → privilege escalation
   - Open redirect → OAuth token theft → account takeover
3. For each potential chain:
   - Can step 1 realistically be achieved?
   - Does step 1 output enable step 2?
   - What's the final impact?
4. Look for AMPLIFICATION:
   - One SQLi → dump all credentials → compromise all accounts
   - One admin takeover → backdoor all users`,
    whatToFind: [
      'XSS + sensitive action without CSRF protection',
      'IDOR + bulk enumeration = dump all user data',
      'Error message leaks + targeted SQLi',
      'Open redirect + OAuth flow = token theft',
      'SSRF + cloud metadata = credential theft',
      'Low-priv user + missing authz = admin actions',
    ],
    exampleVulnerability: `// CHAIN: Reflected XSS → Admin Account Takeover

// Step 1: Reflected XSS in search (low severity alone)
app.get('/search', (req, res) => {
  res.send(\`Results for: \${req.query.q}\`);  // XSS
});

// Step 2: Admin action without CSRF protection
app.post('/admin/make-admin', requireAdmin, (req, res) => {
  await makeUserAdmin(req.body.userId);  // No CSRF token!
});

// ATTACK: Send admin link with XSS payload that:
// 1. Executes in admin's browser
// 2. Calls /admin/make-admin with attacker's userId
// 3. Attacker is now admin

// Individual bugs are medium, chain is CRITICAL`,
  },
  {
    name: 'privilege-escalation-trace',
    level: 'e2e',
    description: 'Trace paths from low-privilege user to high-privilege actions',
    entryPointPatterns: [
      'Role definitions (user, admin, superadmin)',
      'Permission checks',
      'Admin-only endpoints',
      'User data access patterns',
    ],
    traceInstructions: `1. Map the PERMISSION MODEL:
   - What roles exist? (user, admin, etc.)
   - What can each role do?
   - How are roles assigned/checked?
2. For EACH admin/elevated action:
   - What checks prevent normal users?
   - Can checks be bypassed? (parameter tampering, type confusion)
   - Is role checked at every layer or just the edge?
3. Find ESCALATION PATHS:
   - User can modify their own role field
   - Admin check uses user-controlled data
   - Internal API doesn't re-check permissions
   - Race condition in permission update`,
    whatToFind: [
      'Role field modifiable via mass assignment',
      'Admin check compares string (user can inject "admin")',
      'Permission cached and not re-validated',
      'GraphQL allows querying role mutation directly',
      'Different endpoints with different permission checks for same action',
    ],
    exampleVulnerability: `// Mass assignment allows role modification
app.put('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);  // BUG: Assigns ALL fields including role!
  await user.save();
});

// Attacker sends: PUT /users/123 { "role": "admin" }

// Or: Permission check uses string comparison
if (user.role == 'admin') { ... }  // BUG: '0' == 0, type coercion issues

// Or: Different layers, different checks
// REST: requireAdmin middleware
// GraphQL: No permission check on same resolver`,
  },
  {
    name: 'session-lifecycle-trace',
    level: 'e2e',
    description: 'Trace complete session lifecycle for security gaps',
    entryPointPatterns: [
      'Login/authentication endpoints',
      'Token/session generation',
      'Token validation functions',
      'Logout/session termination',
    ],
    traceInstructions: `1. TRACE LOGIN FLOW:
   - How are credentials verified?
   - How is session/token generated?
   - Is token random enough? (not Math.random!)
   - What's stored in token? (user ID, role, etc.)
2. TRACE VALIDATION FLOW:
   - How is token validated on each request?
   - Is signature verified?
   - Is expiration checked?
   - Can token be forged?
3. TRACE LOGOUT FLOW:
   - Is token actually invalidated?
   - Server-side session destroyed?
   - Can old token still be used?
4. Find GAPS:
   - Token never expires
   - Logout doesn't invalidate token (JWT with no blacklist)
   - Token can be generated without proper auth
   - Token content can be modified (weak signature)`,
    whatToFind: [
      'JWT with none algorithm accepted',
      'Session token generated with Math.random()',
      'Token not invalidated on logout (replay attacks)',
      'Token expiration not checked on validation',
      'Refresh token rotation not implemented',
      'Session fixation (token not regenerated on login)',
    ],
    exampleVulnerability: `// Token generated with weak randomness
function generateToken() {
  return Math.random().toString(36).slice(2);  // PREDICTABLE!
}

// JWT 'none' algorithm accepted
const decoded = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

// Logout doesn't invalidate token
app.post('/logout', (req, res) => {
  res.clearCookie('token');  // Client-side only!
  // BUG: Token still valid! Attacker with token can still use it
});

// Token never expires
const token = jwt.sign({ userId }, secret);  // No expiresIn!`,
  },
  {
    name: 'user-journey-simulation',
    level: 'e2e',
    description: 'Simulate complete user journeys and find security gaps',
    entryPointPatterns: [
      'Signup/registration flow',
      'Login flow',
      'Password reset flow',
      'Critical actions (payment, delete, transfer)',
    ],
    traceInstructions: `1. MAP CRITICAL JOURNEYS:
   - Signup → email verify → login → use app
   - Forgot password → reset link → new password
   - Browse → add to cart → checkout → payment
   - Settings → delete account → confirm
2. For EACH journey, check at EVERY step:
   - Can step be skipped?
   - Can step be replayed?
   - Can step be done out of order?
   - Is state properly tracked?
3. Find GAPS:
   - Email verification can be skipped
   - Password reset token doesn't expire
   - Payment completes before verification
   - Delete confirmation can be bypassed`,
    whatToFind: [
      'Email verification skippable (access features without verifying)',
      'Password reset token reusable (use same link multiple times)',
      'Checkout flow can skip payment verification',
      'State machine allows illegal transitions',
      'CSRF on critical actions (delete, transfer)',
      'Rate limiting missing on sensitive operations',
    ],
    exampleVulnerability: `// Email verification bypassable
app.post('/signup', async (req, res) => {
  const user = await User.create({ ...req.body, verified: false });
  sendVerificationEmail(user);
  res.json({ token: generateToken(user) });  // BUG: Token given before verification!
});

// User can access protected features without verifying email

// Or: Password reset token never expires
app.post('/forgot-password', async (req, res) => {
  const token = generateToken();
  await saveResetToken(req.body.email, token);  // No expiration!
  // Token valid forever - old emails can be used to reset
});

// Or: Payment can be skipped
app.post('/complete-order', async (req, res) => {
  const order = await Order.findById(req.body.orderId);
  order.status = 'completed';  // BUG: No check if payment succeeded!
  await order.save();
});`,
  },
  {
    name: 'api-contract-verification',
    level: 'e2e',
    description: 'Verify API actually enforces what types/docs promise',
    entryPointPatterns: [
      'OpenAPI/Swagger definitions',
      'TypeScript API types',
      'GraphQL schema',
      'API documentation',
    ],
    traceInstructions: `1. Find API CONTRACT (OpenAPI, types, docs):
   - What fields are required?
   - What are the valid values/ranges?
   - What authentication is required?
2. Compare CONTRACT vs IMPLEMENTATION:
   - Does code validate all required fields?
   - Does code enforce value ranges?
   - Does code check auth as documented?
3. Find MISMATCHES:
   - Docs say "required" but code has default
   - Type says "number" but code accepts string
   - Docs say "admin only" but no middleware
4. These mismatches are BUGS:
   - Security controls documented but not implemented
   - Validation promised but not enforced`,
    whatToFind: [
      'OpenAPI says required but code has fallback',
      'Type says admin-only but no role check',
      'Schema says max 100 but code allows more',
      'Docs say authenticated but route is public',
      'GraphQL schema allows query that should be forbidden',
    ],
    exampleVulnerability: `// OpenAPI says adminOnly: true
// paths:
//   /admin/users:
//     get:
//       security:
//         - adminAuth: []

// But implementation has no check!
app.get('/admin/users', async (req, res) => {  // No auth middleware!
  const users = await User.find();
  res.json(users);
});

// Or: TypeScript type vs runtime
interface CreateUserInput {
  name: string;
  email: string;
  role?: 'user';  // Only 'user' allowed
}

// But implementation:
const user = await User.create(req.body);  // No validation! role:'admin' accepted`,
  },
];

/**
 * Get flow passes by level
 */
export function getFlowPassesByLevel(level: 'integration' | 'e2e'): FlowPassConfig[] {
  return FLOW_PASSES.filter(p => p.level === level);
}

/**
 * Get all flow pass names in recommended order
 */
export function getFlowPassOrder(): string[] {
  // Integration first (builds understanding), then E2E (uses that understanding)
  return [
    // Integration passes
    'auth-flow-trace',
    'data-flow-trace',
    'validation-boundary-trace',
    'error-propagation-trace',
    'trust-boundary-trace',
    // E2E passes
    'attack-chain-analysis',
    'privilege-escalation-trace',
    'session-lifecycle-trace',
    'user-journey-simulation',
    'api-contract-verification',
  ];
}

/**
 * Get flow pass config by name
 */
export function getFlowPassConfig(name: string): FlowPassConfig | undefined {
  return FLOW_PASSES.find(p => p.name === name);
}
