/**
 * Risk Profiler - Deterministic Risk Analysis
 *
 * Analyzes understanding.json + project structure to derive a RiskProfile.
 * No LLM calls - pure heuristics and pattern matching.
 *
 * Detection is CAPABILITY-BASED, not vendor-specific:
 * - Keywords use word-boundary matching against descriptions and features
 * - Dependencies are matched by both known names AND segment patterns
 * - File paths match structural conventions across any framework
 *
 * 42 domains across 8 categories:
 *   Identity & Access: auth, session, oauth, access-control, multi-tenancy, mfa
 *   Data Layer: database, cache, search, serialization, storage
 *   Communication: api, graphql, grpc, realtime, email, webhook, queue, notification
 *   Security Infra: crypto, cors, csrf, redirect, rate-limiting, config, logging
 *   Content & Files: file-upload, templating, xml, pdf-generation, image-processing, cms
 *   Business Logic: payments, e-commerce, subscription, workflow, feature-flags
 *   Data Movement: export, import
 *   Advanced: ml-ai, proxy, cron
 */

import {
  CodebaseUnderstanding,
  RiskProfile,
  HotPath,
  CustomPassConfig,
  SkipReason,
} from '../types.js';

// ─────────────────────────────────────────────────────────────
// Domain Definition
// ─────────────────────────────────────────────────────────────

interface DomainDef {
  /** Capability keywords matched against description/features (word-boundary) */
  keywords: string[];
  /** Known dependency names (exact match on dep key) */
  knownDeps: string[];
  /** Patterns matched against individual segments of dependency names (split on [-/@]) */
  depSegments: string[];
  /** File/directory path patterns */
  pathPatterns: RegExp[];
  /** Custom scanning passes for this domain */
  passes: CustomPassConfig[];
}

/**
 * All known domains with detection signals and custom passes.
 * Each domain represents a CAPABILITY, not a vendor.
 */
const DOMAINS: Record<string, DomainDef> = {

  // ═══════════════════════════════════════════════════════════
  // IDENTITY & ACCESS
  // ═══════════════════════════════════════════════════════════

  'auth': {
    keywords: ['auth', 'login', 'signin', 'sign-in', 'signup', 'sign-up', 'register', 'password', 'credential', 'authenticate', 'identity'],
    knownDeps: ['bcrypt', 'bcryptjs', 'argon2', 'passport', 'next-auth', '@auth/core', 'lucia', 'better-auth', '@supabase/auth-helpers-nextjs'],
    depSegments: ['auth', 'login', 'credential', 'identity'],
    pathPatterns: [/auth[/\\]/, /login[/\\]/, /signin[/\\]/, /signup[/\\]/, /register[/\\]/],
    passes: [
      { id: 'credential-handling', phase: 'unit', category: 'auth-bypass', description: 'Check credential handling safety. Look for: passwords stored in plaintext or weak hashes (MD5, SHA1), missing salt in hashing, timing-safe comparison not used for password/token verification, credentials logged or included in error messages.' },
      { id: 'brute-force-protection', phase: 'integration', category: 'auth-bypass', description: 'Check for brute force protection on authentication endpoints. Look for: login endpoints without rate limiting, missing account lockout after failed attempts, no CAPTCHA or progressive delays, enumeration possible via different error messages for valid vs invalid usernames.' },
    ],
  },

  'session': {
    keywords: ['session', 'jwt', 'token', 'cookie', 'refresh token'],
    knownDeps: ['jsonwebtoken', 'jose', 'express-session', 'cookie-session', 'iron-session', 'koa-session', 'fastify-secure-session', 'connect-redis', 'connect-mongo'],
    depSegments: ['session', 'jwt', 'token'],
    pathPatterns: [/sessions?[/\\]/, /tokens?[/\\]/],
    passes: [
      { id: 'session-fixation', phase: 'integration', category: 'auth-bypass', description: 'Check for session fixation vulnerabilities. Look for: session ID not regenerated after login, pre-authentication session IDs reused after authentication, session tokens set before credential verification, session cookies missing Secure/HttpOnly/SameSite flags.' },
      { id: 'token-lifecycle', phase: 'e2e', category: 'auth-bypass', description: 'Trace full token lifecycle from creation to invalidation. Look for: tokens that never expire, logout not invalidating server-side sessions, refresh tokens not rotated on use, JWT with weak or missing signature verification, tokens stored in localStorage (XSS accessible).' },
    ],
  },

  'oauth': {
    keywords: ['oauth', 'openid', 'oidc', 'sso', 'saml', 'single sign-on', 'social login', 'federated'],
    knownDeps: ['oauth2-server', 'openid-client', 'grant', 'simple-oauth2', 'passport-google-oauth20', 'passport-github2', 'passport-facebook', '@auth0/nextjs-auth0', 'next-auth'],
    depSegments: ['oauth', 'openid', 'oidc', 'saml', 'sso'],
    pathPatterns: [/oauth[/\\]/, /sso[/\\]/, /openid[/\\]/],
    passes: [
      { id: 'oauth-redirect-validation', phase: 'integration', category: 'auth-bypass', description: 'Check OAuth redirect URI validation. Look for: redirect_uri not validated against allowlist, partial matching allowing subdomain takeover (example.com.evil.com), open redirects in OAuth callback flow, missing state parameter for CSRF protection, PKCE not implemented for public clients.' },
    ],
  },

  'access-control': {
    keywords: ['authorization', 'rbac', 'role', 'permission', 'acl', 'access control', 'privilege', 'policy', 'guard', 'middleware'],
    knownDeps: ['casl', '@casl/ability', 'accesscontrol', 'casbin', 'node-casbin', 'role-acl'],
    depSegments: ['rbac', 'acl', 'permission', 'policy', 'guard'],
    pathPatterns: [/permissions?[/\\]/, /roles?[/\\]/, /policies[/\\]/, /guards?[/\\]/, /middleware[/\\]/, /authorization[/\\]/],
    passes: [
      { id: 'horizontal-access', phase: 'integration', category: 'auth-bypass', description: 'Check for horizontal privilege escalation (IDOR). Look for: resource access using user-supplied IDs without ownership verification, missing tenant/user scoping on database queries, API endpoints that accept arbitrary user/resource IDs without checking the requester owns them.' },
      { id: 'vertical-escalation', phase: 'e2e', category: 'auth-bypass', description: 'Check for vertical privilege escalation. Look for: role field modifiable via mass assignment, role checks using client-supplied data, admin endpoints with inconsistent permission checks across layers, permission cached and not re-validated after role change.' },
    ],
  },

  'multi-tenancy': {
    keywords: ['tenant', 'multi-tenant', 'organization', 'workspace', 'team', 'namespace'],
    knownDeps: [],
    depSegments: ['tenant', 'multitenancy'],
    pathPatterns: [/tenants?[/\\]/, /organizations?[/\\]/, /workspaces?[/\\]/],
    passes: [
      { id: 'tenant-isolation', phase: 'integration', category: 'auth-bypass', description: 'Check tenant data isolation. Look for: database queries without tenant ID filter, cross-tenant data leakage via shared caches, tenant ID from user input instead of authenticated session, missing tenant context in background jobs/queues, shared resources without tenant scoping.' },
    ],
  },

  'mfa': {
    keywords: ['mfa', 'two-factor', '2fa', 'totp', 'otp', 'authenticator', 'verification code'],
    knownDeps: ['otplib', 'speakeasy', 'notp', 'node-2fa'],
    depSegments: ['otp', 'totp', 'mfa', '2fa'],
    pathPatterns: [/mfa[/\\]/, /2fa[/\\]/, /otp[/\\]/, /verification[/\\]/],
    passes: [
      { id: 'mfa-bypass', phase: 'integration', category: 'auth-bypass', description: 'Check for MFA bypass vulnerabilities. Look for: MFA step skippable by directly accessing post-MFA endpoints, OTP codes not rate-limited (brute-forceable), backup codes not single-use, MFA enrollment not required for sensitive operations, TOTP window too large.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // DATA LAYER
  // ═══════════════════════════════════════════════════════════

  'database': {
    keywords: ['database', 'sql', 'nosql', 'orm', 'migration', 'repository', 'persistence', 'data layer', 'data store'],
    knownDeps: ['prisma', '@prisma/client', 'typeorm', 'sequelize', 'knex', 'mongoose', 'drizzle-orm', 'pg', 'mysql2', 'better-sqlite3', 'mongodb', 'neo4j-driver', 'cassandra-driver', 'couchbase', 'dynamodb', '@aws-sdk/client-dynamodb', 'mikro-orm', 'objection', 'bookshelf', 'waterline', 'massive'],
    depSegments: ['db', 'sql', 'mongo', 'postgres', 'mysql', 'sqlite', 'dynamo', 'cassandra', 'couch', 'neo4j', 'orm'],
    pathPatterns: [/database[/\\]/, /db[/\\]/, /models?[/\\]/, /migrations?[/\\]/, /repositories?[/\\]/, /entities[/\\]/, /schemas?[/\\]/],
    passes: [
      { id: 'query-safety', phase: 'unit', category: 'injection', description: 'Check for unsafe database query construction. Look for: string concatenation/interpolation in SQL queries, raw queries with user input, ORM methods that accept raw SQL fragments (e.g., Sequelize.literal, knex.raw), missing parameterization, NoSQL injection via object injection in MongoDB queries ($gt, $ne operators from user input).' },
      { id: 'mass-assignment', phase: 'unit', category: 'data-validation', description: 'Check for mass assignment vulnerabilities. Look for: Object.assign(model, req.body), spread operator on user input into models, ORM create/update with unfiltered user input, missing field allowlists/denylists on model operations.' },
    ],
  },

  'cache': {
    keywords: ['cache', 'caching', 'memoize', 'ttl', 'invalidation'],
    knownDeps: ['ioredis', 'redis', 'node-cache', 'lru-cache', 'keyv', 'catbox', 'cache-manager', 'memcached'],
    depSegments: ['cache', 'redis', 'memcache'],
    pathPatterns: [/cache[/\\]/, /caching[/\\]/],
    passes: [
      { id: 'cache-poisoning', phase: 'integration', category: 'injection', description: 'Check for cache poisoning vulnerabilities. Look for: cache keys derived from user-controlled headers (Host, X-Forwarded-Host), cached responses including user-specific data served to other users, missing cache key scoping by user/session, cache stampede allowing timing attacks.' },
    ],
  },

  'search': {
    keywords: ['search', 'full-text', 'indexing', 'autocomplete', 'typeahead', 'facet'],
    knownDeps: ['@elastic/elasticsearch', 'algoliasearch', 'meilisearch', 'typesense', 'lunr', 'flexsearch', 'solr-client', 'minisearch'],
    depSegments: ['search', 'elastic', 'solr'],
    pathPatterns: [/search[/\\]/, /indexing[/\\]/],
    passes: [
      { id: 'search-injection', phase: 'unit', category: 'injection', description: 'Check for search query injection. Look for: user input passed directly to Elasticsearch/Lucene query DSL, unescaped special characters in search queries (*, ?, ~), search queries that can access unauthorized indices or fields, autocomplete endpoints leaking private data.' },
    ],
  },

  'serialization': {
    keywords: ['serialize', 'deserialize', 'marshal', 'unmarshal', 'parse', 'protobuf', 'msgpack', 'avro'],
    knownDeps: ['protobufjs', 'msgpack5', '@msgpack/msgpack', 'avsc', 'bson', 'flatbuffers', 'js-yaml', 'yaml', 'fast-xml-parser', 'class-transformer'],
    depSegments: ['serial', 'proto', 'msgpack', 'avro', 'marshal'],
    pathPatterns: [/serializ[/\\]/, /marshal[/\\]/, /proto[/\\]/],
    passes: [
      { id: 'deserialization-safety', phase: 'unit', category: 'injection', description: 'Check for unsafe deserialization. Look for: eval() or Function() used for deserialization, YAML.load (unsafe) instead of YAML.safeLoad, JSON.parse of untrusted input without schema validation, prototype pollution via __proto__ or constructor.prototype in parsed objects, object spread of deserialized untrusted data.' },
    ],
  },

  'storage': {
    keywords: ['storage', 'object storage', 'blob', 'bucket', 'file system', 'artifact'],
    knownDeps: ['@aws-sdk/client-s3', '@google-cloud/storage', '@azure/storage-blob', 'minio', 'cloudinary'],
    depSegments: ['storage', 's3', 'blob', 'bucket', 'minio'],
    pathPatterns: [/storage[/\\]/, /blobs?[/\\]/, /buckets?[/\\]/, /artifacts?[/\\]/],
    passes: [
      { id: 'storage-access-control', phase: 'integration', category: 'auth-bypass', description: 'Check cloud storage access controls. Look for: pre-signed URLs with excessive expiry times, public bucket/container access misconfiguration, missing ACL checks on file download endpoints, user-controlled storage paths allowing access to other users files, SSRF via storage URL construction.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // COMMUNICATION
  // ═══════════════════════════════════════════════════════════

  'api': {
    keywords: ['api', 'rest', 'endpoint', 'route', 'controller', 'handler', 'middleware', 'http'],
    knownDeps: ['express', 'fastify', '@nestjs/core', 'koa', 'hapi', '@hapi/hapi', 'restify', 'polka', 'h3', 'hono', 'elysia', '@trpc/server', 'tsoa', 'routing-controllers'],
    depSegments: ['express', 'fastify', 'koa', 'hapi', 'server', 'router', 'http'],
    pathPatterns: [/api[/\\]/, /routes?[/\\]/, /controllers?[/\\]/, /endpoints?[/\\]/, /handlers?[/\\]/],
    passes: [
      { id: 'api-input-validation', phase: 'unit', category: 'data-validation', description: 'Check API input validation completeness. Look for: req.body/query/params used without schema validation, numeric parameters parsed without NaN/range checks, array inputs without length limits, nested object inputs without depth limits, missing Content-Type enforcement.' },
    ],
  },

  'graphql': {
    keywords: ['graphql', 'gql', 'schema', 'resolver', 'mutation', 'subscription'],
    knownDeps: ['graphql', 'apollo-server', '@apollo/server', 'apollo-server-express', 'graphql-yoga', 'mercurius', 'type-graphql', 'nexus', 'pothos', '@graphql-tools/schema', 'graphql-ws'],
    depSegments: ['graphql', 'gql', 'apollo'],
    pathPatterns: [/graphql[/\\]/, /gql[/\\]/, /resolvers?[/\\]/, /mutations?[/\\]/],
    passes: [
      { id: 'graphql-depth-limiting', phase: 'unit', category: 'resource-leak', description: 'Check for GraphQL denial of service vectors. Look for: missing query depth limiting, missing query complexity analysis, no limit on batch/alias operations, introspection enabled in production, missing pagination limits on list fields, N+1 query patterns in resolvers without dataloader.' },
      { id: 'graphql-authorization', phase: 'integration', category: 'auth-bypass', description: 'Check GraphQL authorization. Look for: resolvers without auth directives/guards, sensitive fields queryable without permission checks, mutations accessible without proper role verification, subscription channels leaking data across users.' },
    ],
  },

  'grpc': {
    keywords: ['grpc', 'protobuf', 'rpc', 'proto', 'service definition'],
    knownDeps: ['@grpc/grpc-js', '@grpc/proto-loader', 'grpc', 'protobufjs', 'ts-proto', 'nice-grpc', '@connectrpc/connect'],
    depSegments: ['grpc', 'proto'],
    pathPatterns: [/grpc[/\\]/, /protos?[/\\]/, /rpc[/\\]/],
    passes: [
      { id: 'grpc-validation', phase: 'unit', category: 'data-validation', description: 'Check gRPC input validation. Look for: missing field validation beyond protobuf types (length, range, format), unary calls without deadline/timeout, streaming RPCs without message size limits, missing TLS/mTLS configuration, reflection service enabled in production.' },
    ],
  },

  'realtime': {
    keywords: ['realtime', 'real-time', 'websocket', 'socket', 'live', 'sse', 'server-sent events', 'long-polling', 'pub/sub', 'pubsub'],
    knownDeps: ['socket.io', 'ws', 'pusher', 'ably', '@supabase/realtime-js', 'sockjs', 'engine.io', 'faye', 'primus', '@fastify/websocket', 'graphql-ws'],
    depSegments: ['socket', 'realtime', 'sse', 'pubsub', 'websocket'],
    pathPatterns: [/realtime[/\\]/, /websockets?[/\\]/, /sockets?[/\\]/, /live[/\\]/, /events?[/\\]/, /sse[/\\]/],
    passes: [
      { id: 'realtime-auth', phase: 'integration', category: 'auth-bypass', description: 'Check realtime connection authentication. Look for: WebSocket/SSE connections accepted without auth verification, missing per-message authorization (auth checked only on connect), missing origin validation on WebSocket upgrade, event subscriptions allowing access to other users channels.' },
      { id: 'event-injection', phase: 'unit', category: 'injection', description: 'Check for event injection in realtime systems. Look for: user-controlled event names passed to emit/broadcast, unvalidated payloads broadcast to other clients, missing input sanitization on WebSocket messages, client able to trigger server-side events by name.' },
    ],
  },

  'email': {
    keywords: ['email sending', 'smtp', 'mailer', 'newsletter', 'transactional email', 'email service', 'email template', 'send email', 'email notification'],
    knownDeps: ['nodemailer', '@sendgrid/mail', 'postmark', 'mailgun-js', '@aws-sdk/client-ses', 'resend', 'react-email', 'mjml', 'email-templates', 'bull-board'],
    depSegments: ['mail', 'email', 'smtp', 'sendgrid', 'postmark'],
    pathPatterns: [/emails?[/\\]/, /mailers?[/\\]/, /newsletters?[/\\]/],
    passes: [
      { id: 'email-header-injection', phase: 'unit', category: 'injection', description: 'Check for email header injection. Look for: user input in email headers (To, From, CC, BCC, Subject) without newline stripping, template injection in email bodies (SSTI), user-controlled URLs in email templates (phishing), missing SPF/DKIM/DMARC consideration, email content including unsanitized user data.' },
    ],
  },

  'webhook': {
    keywords: ['webhook', 'callback url', 'event notification', 'http callback'],
    knownDeps: ['svix', '@octokit/webhooks', 'stripe'],
    depSegments: ['webhook', 'callback'],
    pathPatterns: [/webhooks?[/\\]/, /callbacks?[/\\]/],
    passes: [
      { id: 'webhook-verification', phase: 'integration', category: 'auth-bypass', description: 'Check webhook security. Look for: incoming webhooks without signature verification (HMAC, asymmetric), webhook endpoints without IP allowlisting or authentication, missing replay protection (no timestamp validation), SSRF via outgoing webhook URLs controlled by users, webhook payloads processed without validation.' },
    ],
  },

  'queue': {
    keywords: ['queue', 'job', 'worker', 'background job', 'task queue', 'message broker', 'consumer', 'producer'],
    knownDeps: ['bull', 'bullmq', 'amqplib', 'kafkajs', '@aws-sdk/client-sqs', 'bee-queue', 'agenda', 'pg-boss', 'faktory-worker', 'celery-node', 'rsmq'],
    depSegments: ['queue', 'worker', 'amqp', 'kafka', 'sqs', 'rabbit', 'bull'],
    pathPatterns: [/queues?[/\\]/, /jobs?[/\\]/, /workers?[/\\]/, /consumers?[/\\]/, /producers?[/\\]/],
    passes: [
      { id: 'queue-message-safety', phase: 'unit', category: 'injection', description: 'Check queue message safety. Look for: deserialization of untrusted queue messages without schema validation, job data used in shell commands or SQL queries without sanitization, missing dead-letter queue handling, job retry without idempotency, user-controlled job types or queue names enabling unauthorized actions.' },
    ],
  },

  'notification': {
    keywords: ['notification', 'push notification', 'alert', 'fcm', 'apns'],
    knownDeps: ['firebase-admin', 'web-push', '@aws-sdk/client-sns', 'onesignal-node', 'expo-server-sdk', 'apn', 'node-pushnotifications'],
    depSegments: ['notification', 'push', 'fcm', 'apns', 'sns'],
    pathPatterns: [/notifications?[/\\]/, /push[/\\]/, /alerts?[/\\]/],
    passes: [
      { id: 'notification-auth', phase: 'integration', category: 'auth-bypass', description: 'Check notification subscription authorization. Look for: push notification subscriptions without user authentication, ability to subscribe to other users notification channels, notification payloads containing sensitive data sent to unverified devices, missing subscription ownership validation on unsubscribe.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // SECURITY INFRASTRUCTURE
  // ═══════════════════════════════════════════════════════════

  'crypto': {
    keywords: ['encrypt', 'decrypt', 'cipher', 'hash', 'hmac', 'signing', 'signature', 'key management', 'kms', 'vault'],
    knownDeps: ['crypto-js', 'tweetnacl', 'libsodium-wrappers', '@aws-sdk/client-kms', '@google-cloud/kms', 'node-forge', 'openpgp', 'sodium-native', 'jose'],
    depSegments: ['crypto', 'cipher', 'encrypt', 'hash', 'kms', 'vault', 'sodium', 'nacl'],
    pathPatterns: [/crypto[/\\]/, /encryption[/\\]/, /keys?[/\\]/, /vault[/\\]/, /certs?[/\\]/],
    passes: [
      { id: 'weak-crypto', phase: 'unit', category: 'secrets-exposure', description: 'Check for weak cryptographic practices. Look for: MD5/SHA1 used for security purposes (password hashing, signatures), ECB mode encryption, static/hardcoded IVs or salts, Math.random() for security-sensitive values, insufficient key lengths (RSA < 2048, AES < 128), deprecated algorithms (DES, 3DES, RC4).' },
      { id: 'key-management', phase: 'integration', category: 'secrets-exposure', description: 'Check key management practices. Look for: encryption keys hardcoded in source, keys stored in environment variables without KMS wrapping, missing key rotation mechanism, private keys committed to repository, symmetric keys shared across services, keys logged or included in error messages.' },
    ],
  },

  'cors': {
    keywords: ['cors', 'cross-origin', 'origin policy', 'access-control-allow'],
    knownDeps: ['cors', '@fastify/cors', '@koa/cors'],
    depSegments: ['cors'],
    pathPatterns: [/cors[/\\]/],
    passes: [
      { id: 'cors-misconfiguration', phase: 'unit', category: 'auth-bypass', description: 'Check CORS configuration safety. Look for: Access-Control-Allow-Origin set to wildcard (*) with credentials, origin reflected without allowlist validation, Access-Control-Allow-Methods too permissive, Access-Control-Max-Age too long, missing Vary: Origin header when origin is dynamic, regex-based origin matching with bypasses.' },
    ],
  },

  'csrf': {
    keywords: ['csrf', 'xsrf', 'cross-site request forgery', 'anti-forgery', 'csrf token'],
    knownDeps: ['csurf', 'csrf-csrf', 'lusca', 'csrf'],
    depSegments: ['csrf', 'xsrf'],
    pathPatterns: [/csrf[/\\]/],
    passes: [
      { id: 'csrf-protection', phase: 'integration', category: 'auth-bypass', description: 'Check CSRF protection on state-changing endpoints. Look for: POST/PUT/DELETE endpoints without CSRF token validation, CSRF tokens not bound to user session, SameSite cookie attribute not set, token transmitted in URL query parameter (leaked via Referer), missing CSRF protection on logout/password-change/email-change endpoints.' },
    ],
  },

  'redirect': {
    keywords: ['redirect', 'redirect_uri', 'return_url', 'next_url', 'callback'],
    knownDeps: [],
    depSegments: [],
    pathPatterns: [],
    passes: [
      { id: 'open-redirect', phase: 'unit', category: 'injection', description: 'Check for open redirect vulnerabilities. Look for: user-controlled redirect URLs without allowlist validation, URL parsing that can be bypassed (e.g., //evil.com, /\\evil.com, /%09/evil.com), redirect after login using unvalidated return_url parameter, JavaScript protocol in redirect URLs (javascript:).' },
    ],
  },

  'rate-limiting': {
    keywords: ['rate limit', 'throttle', 'throttling', 'rate-limit', 'quota', 'ddos protection'],
    knownDeps: ['express-rate-limit', 'rate-limiter-flexible', 'bottleneck', '@fastify/rate-limit', 'limiter', 'p-throttle', 'p-limit'],
    depSegments: ['ratelimit', 'throttle', 'limiter'],
    pathPatterns: [/rate-limit[/\\]/, /throttl[/\\]/, /limiters?[/\\]/],
    passes: [
      { id: 'rate-limit-bypass', phase: 'integration', category: 'auth-bypass', description: 'Check rate limiting effectiveness. Look for: rate limits based on IP only (bypassable via proxies/rotating IPs), missing rate limits on login/password-reset/OTP-verification endpoints, rate limit state in local memory (not shared across instances), X-Forwarded-For header trusted without validation, rate limit key not including API key or user ID.' },
    ],
  },

  'config': {
    keywords: ['config', 'configuration', 'environment', 'settings', 'env var', 'dotenv'],
    knownDeps: ['dotenv', 'config', 'convict', 'envalid', '@nestjs/config', 'env-var', 'nconf'],
    depSegments: ['config', 'dotenv', 'env'],
    pathPatterns: [/config[/\\]/, /settings[/\\]/],
    passes: [
      { id: 'config-exposure', phase: 'unit', category: 'secrets-exposure', description: 'Check configuration security. Look for: default credentials in config files, debug mode enabled by default, secrets with fallback values in code, config files with overly permissive file permissions, environment-specific configs committed to repository, API keys or database URLs in client-side bundles.' },
    ],
  },

  'logging': {
    keywords: ['logging', 'logger', 'audit trail', 'audit log', 'access log', 'activity log', 'structured logging', 'log aggregation'],
    knownDeps: ['winston', 'pino', 'bunyan', 'morgan', 'log4js', 'signale', 'tslog', 'roarr', 'loglevel'],
    depSegments: ['log', 'logger', 'logging', 'audit'],
    pathPatterns: [/loggers?[/\\]/, /logging[/\\]/, /audit[/\\]/],
    passes: [
      { id: 'log-injection', phase: 'unit', category: 'injection', description: 'Check for log injection and data leakage. Look for: user input written to logs without sanitization (newline injection for log forging), PII/passwords/tokens/credit-card numbers in log output, stack traces with sensitive info logged in production, ANSI escape sequences in log output (terminal injection).' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // CONTENT & FILES
  // ═══════════════════════════════════════════════════════════

  'file-upload': {
    keywords: ['upload', 'file upload', 'multipart', 'attachment', 'media upload', 'image upload', 'document upload'],
    knownDeps: ['multer', 'busboy', 'formidable', 'multiparty', '@fastify/multipart', 'express-fileupload'],
    depSegments: ['upload', 'multipart'],
    pathPatterns: [/uploads?[/\\]/, /attachments?[/\\]/, /media[/\\]/],
    passes: [
      { id: 'upload-safety', phase: 'unit', category: 'injection', description: 'Check file upload safety. Look for: file type validation using extension only (not magic bytes/MIME), no file size limits, uploaded files stored with user-controlled names (path traversal), executable files accepted (.php, .jsp, .aspx, .sh), no antivirus/malware scanning, files served from same origin as application.' },
      { id: 'path-traversal-upload', phase: 'integration', category: 'injection', description: 'Check for path traversal in file operations. Look for: user-controlled file paths passed to fs.readFile/writeFile/unlink, directory traversal via ../.. in filenames, symlink following in upload/download directories, zip slip in archive extraction, file path construction from user input without canonicalization.' },
    ],
  },

  'templating': {
    keywords: ['template', 'render', 'view engine', 'handlebars', 'mustache', 'ejs', 'pug', 'jinja', 'server-side rendering'],
    knownDeps: ['ejs', 'pug', 'handlebars', 'mustache', 'nunjucks', 'eta', 'liquidjs', 'marko', 'hbs', 'consolidate'],
    depSegments: ['template', 'ejs', 'pug', 'handlebars', 'mustache', 'nunjucks'],
    pathPatterns: [/templates?[/\\]/, /views?[/\\]/, /layouts?[/\\]/, /partials?[/\\]/],
    passes: [
      { id: 'ssti-check', phase: 'unit', category: 'injection', description: 'Check for Server-Side Template Injection (SSTI). Look for: user input directly embedded in template strings before rendering, template compilation with user-controlled template source, sandbox escape in template engines, client-side template injection in Angular/Vue, eval-like constructs in template expressions.' },
    ],
  },

  'xml': {
    keywords: ['xml', 'soap', 'wsdl', 'xslt', 'xpath', 'rss', 'atom', 'svg'],
    knownDeps: ['fast-xml-parser', 'xml2js', 'xmlbuilder', 'xmldom', 'libxmljs', 'soap', 'xpath', 'sax', 'cheerio'],
    depSegments: ['xml', 'soap', 'xslt', 'xpath'],
    pathPatterns: [/xml[/\\]/, /soap[/\\]/],
    passes: [
      { id: 'xxe-check', phase: 'unit', category: 'injection', description: 'Check for XML External Entity (XXE) injection. Look for: XML parsers with external entity processing enabled, DTD processing not disabled, XSLT processing of user-supplied stylesheets, XPath queries with user input, billion laughs/entity expansion not limited, SVG files parsed without sanitization.' },
    ],
  },

  'pdf-generation': {
    keywords: ['pdf', 'document generation', 'report generation', 'invoice generation', 'receipt'],
    knownDeps: ['puppeteer', 'pdfkit', 'jspdf', 'pdfmake', 'html-pdf', 'wkhtmltopdf', '@react-pdf/renderer', 'pdf-lib', 'chromiumly'],
    depSegments: ['pdf', 'pdfkit', 'wkhtml'],
    pathPatterns: [/pdf[/\\]/, /reports?[/\\]/, /documents?[/\\]/],
    passes: [
      { id: 'pdf-ssrf', phase: 'integration', category: 'injection', description: 'Check for SSRF via PDF generation. Look for: HTML-to-PDF converters rendering user-supplied HTML (can access internal URLs via <img>, <link>, <iframe>), user-controlled URLs in PDF generation (fetch internal resources), CSS @import/@font-face with user-controlled URLs, JavaScript execution in headless browser PDF generation.' },
    ],
  },

  'image-processing': {
    keywords: ['image processing', 'image resize', 'thumbnail', 'image manipulation', 'image conversion'],
    knownDeps: ['sharp', 'jimp', 'gm', 'imagemagick', 'image-size', '@squoosh/lib', 'canvas', 'pica', 'blurhash'],
    depSegments: ['image', 'sharp', 'jimp', 'gm', 'imagemagick', 'canvas', 'thumbnail'],
    pathPatterns: [/images?[/\\]/, /thumbnails?[/\\]/, /processing[/\\]/],
    passes: [
      { id: 'image-processing-safety', phase: 'unit', category: 'injection', description: 'Check image processing safety. Look for: ImageMagick/GraphicsMagick command injection via filenames, SVG processing enabling script execution, image bombs (decompression bombs) without size/dimension limits, EXIF data containing scripts not stripped, SSRF via image URL fetching, image processing of untrusted formats without sandboxing.' },
    ],
  },

  'cms': {
    keywords: ['cms', 'content management', 'headless cms', 'blog', 'article', 'editorial'],
    knownDeps: ['strapi', '@strapi/strapi', 'ghost', 'keystone', '@keystone-6/core', 'sanity', 'contentful', 'directus', 'payload'],
    depSegments: ['cms', 'strapi', 'ghost', 'keystone', 'contentful', 'sanity'],
    pathPatterns: [/cms[/\\]/, /content[/\\]/, /articles?[/\\]/, /posts?[/\\]/, /editorial[/\\]/],
    passes: [
      { id: 'cms-xss', phase: 'unit', category: 'injection', description: 'Check for XSS in CMS content rendering. Look for: rich text/markdown rendered without sanitization (dangerouslySetInnerHTML, v-html), user-generated content displayed without HTML encoding, custom embed codes executed without sandboxing, WYSIWYG editor output rendered raw, missing Content-Security-Policy for user content pages.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // BUSINESS LOGIC
  // ═══════════════════════════════════════════════════════════

  'payments': {
    keywords: ['payment', 'checkout', 'billing', 'charge', 'refund', 'invoice', 'transaction', 'payout', 'settlement'],
    knownDeps: ['stripe', '@stripe/stripe-js', '@stripe/react-stripe-js', 'braintree', 'paypal-rest-sdk', '@paypal/checkout-server-sdk', 'square', 'adyen-api', 'razorpay', 'mollie-api-node', 'coinbase-commerce-node', 'paddle-sdk'],
    depSegments: ['payment', 'pay', 'billing', 'checkout', 'stripe', 'braintree', 'paypal', 'razorpay'],
    pathPatterns: [/payments?[/\\]/, /billing[/\\]/, /checkout[/\\]/, /transactions?[/\\]/, /invoices?[/\\]/],
    passes: [
      { id: 'decimal-precision', phase: 'unit', category: 'logic-error', description: 'Check for floating-point arithmetic on monetary values. Look for: Number type for prices/amounts (IEEE 754 precision loss), Math.round on currency calculations, division before multiplication causing rounding errors, missing use of integer cents or Decimal/BigNumber libraries, currency conversion with floating-point.' },
      { id: 'idempotency-check', phase: 'integration', category: 'logic-error', description: 'Verify payment endpoints use idempotency keys. Look for: POST endpoints that charge money without idempotency key validation, missing duplicate payment detection, retry logic that could double-charge, webhook handlers that reprocess already-completed payments.' },
      { id: 'race-condition-financial', phase: 'e2e', category: 'concurrency', description: 'Find race conditions in financial operations. Look for: balance check-then-debit without database transactions/locks, concurrent transfers that could overdraw, non-atomic read-modify-write on account balances, coupon/discount applied multiple times concurrently, parallel refund requests for same order.' },
    ],
  },

  'e-commerce': {
    keywords: ['e-commerce', 'ecommerce', 'shopping cart', 'catalog', 'product', 'inventory', 'order', 'storefront', 'marketplace'],
    knownDeps: ['shopify-api-node', '@shopify/shopify-api', 'medusa-core', 'saleor', 'commercetools'],
    depSegments: ['shop', 'commerce', 'cart', 'catalog', 'inventory', 'storefront'],
    pathPatterns: [/shop[/\\]/, /cart[/\\]/, /products?[/\\]/, /orders?[/\\]/, /catalog[/\\]/, /inventory[/\\]/],
    passes: [
      { id: 'price-manipulation', phase: 'integration', category: 'logic-error', description: 'Check for price manipulation vulnerabilities. Look for: product price sent from client and used directly (not re-fetched from server), discount/coupon amount validated client-side only, total calculated on frontend and trusted by backend, negative quantity or price accepted, race condition between price check and order placement.' },
      { id: 'inventory-race', phase: 'e2e', category: 'concurrency', description: 'Check for inventory race conditions. Look for: stock check-then-decrement without atomic operation, concurrent purchases of last item in stock, overselling via parallel API requests, missing reservation/hold mechanism during checkout flow.' },
    ],
  },

  'subscription': {
    keywords: ['subscription', 'recurring', 'plan', 'tier', 'billing cycle', 'trial', 'upgrade', 'downgrade'],
    knownDeps: [],
    depSegments: ['subscription', 'billing', 'plan'],
    pathPatterns: [/subscriptions?[/\\]/, /plans?[/\\]/, /tiers?[/\\]/],
    passes: [
      { id: 'subscription-bypass', phase: 'integration', category: 'auth-bypass', description: 'Check for subscription/plan bypass. Look for: premium features accessible without active subscription check, plan limits enforced client-side only, trial period manipulation (re-registration), downgrade not revoking access to higher-tier features, subscription status cached and not re-verified.' },
    ],
  },

  'workflow': {
    keywords: ['workflow', 'state machine', 'pipeline', 'approval', 'process', 'step', 'transition'],
    knownDeps: ['xstate', 'bull', 'temporal-sdk', '@temporalio/client', 'inngest', 'trigger.dev'],
    depSegments: ['workflow', 'state-machine', 'pipeline', 'xstate'],
    pathPatterns: [/workflows?[/\\]/, /pipelines?[/\\]/, /state-machines?[/\\]/, /processes?[/\\]/],
    passes: [
      { id: 'state-machine-bypass', phase: 'integration', category: 'logic-error', description: 'Check for state machine/workflow bypass. Look for: direct API access to skip workflow steps (e.g., complete order without payment), missing validation of state transitions (can go from any state to any state), authorization not checked on each transition, concurrent transitions causing invalid states, rollback not cleaning up side effects.' },
    ],
  },

  'feature-flags': {
    keywords: ['feature flag', 'feature toggle', 'feature gate', 'experiment', 'a/b test', 'canary', 'rollout'],
    knownDeps: ['launchdarkly-node-server-sdk', '@unleash/proxy-client-react', 'flagsmith', 'growthbook', '@growthbook/growthbook', 'posthog-node', '@happykit/flags', 'flipt-node'],
    depSegments: ['feature', 'flag', 'toggle', 'experiment'],
    pathPatterns: [/feature-flags?[/\\]/, /flags?[/\\]/, /toggles?[/\\]/, /experiments?[/\\]/],
    passes: [
      { id: 'feature-flag-bypass', phase: 'unit', category: 'auth-bypass', description: 'Check for feature flag bypass. Look for: flag values settable via query parameters or headers, flag evaluation using client-supplied user context without validation, admin features hidden behind flags but not behind auth, flag configuration exposed to client, default flag values granting access.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // DATA MOVEMENT
  // ═══════════════════════════════════════════════════════════

  'export': {
    keywords: ['export', 'download', 'csv export', 'excel', 'spreadsheet', 'report export', 'data dump'],
    knownDeps: ['exceljs', 'xlsx', 'json2csv', 'csv-writer', 'papaparse', 'archiver', 'jszip'],
    depSegments: ['export', 'csv', 'excel', 'xlsx'],
    pathPatterns: [/exports?[/\\]/, /downloads?[/\\]/],
    passes: [
      { id: 'export-injection', phase: 'unit', category: 'injection', description: 'Check for injection in data exports. Look for: CSV injection via formulas (=CMD(), +cmd, @SUM) in cell values, Excel macro injection, user data included in exports without sanitization, export endpoints without authorization (data exfiltration), large export without pagination causing DoS, export containing more data than user should access.' },
    ],
  },

  'import': {
    keywords: ['import', 'upload csv', 'bulk import', 'data import', 'ingest', 'data migration'],
    knownDeps: ['csv-parse', 'papaparse', 'xlsx', 'exceljs', 'multer', 'fast-csv'],
    depSegments: ['import', 'ingest', 'csv-parse'],
    pathPatterns: [/imports?[/\\]/, /ingest[/\\]/, /migrations?[/\\]/],
    passes: [
      { id: 'import-safety', phase: 'unit', category: 'injection', description: 'Check import/ingestion safety. Look for: CSV/Excel parsing without row limits (DoS via huge files), imported data used in queries without sanitization, missing validation of imported data format/schema, zip bomb in archive imports, imported file paths used in file operations (path traversal), deserialization of imported objects.' },
    ],
  },

  // ═══════════════════════════════════════════════════════════
  // ADVANCED
  // ═══════════════════════════════════════════════════════════

  'ml-ai': {
    keywords: ['machine learning', 'artificial intelligence', 'llm', 'ai model', 'ai agent', 'inference', 'prediction', 'embedding', 'vector database', 'prompt engineering', 'chatbot', 'rag pipeline', 'large language model', 'generative ai'],
    knownDeps: ['@anthropic-ai/sdk', 'openai', '@google/generative-ai', 'langchain', '@langchain/core', 'tensorflow', '@tensorflow/tfjs', 'onnxruntime-node', 'transformers', 'pinecone', '@pinecone-database/pinecone', 'chromadb', 'weaviate-ts-client', 'replicate', 'cohere-ai', 'ai'],
    depSegments: ['ml', 'ai', 'llm', 'openai', 'anthropic', 'langchain', 'vector', 'embedding', 'tensorflow', 'onnx'],
    pathPatterns: [/ml[/\\]/, /\bai[/\\]/, /inference[/\\]/, /embeddings?[/\\]/, /llm[/\\]/, /rag[/\\]/],
    passes: [
      { id: 'prompt-injection', phase: 'unit', category: 'injection', description: 'Check for prompt injection in LLM/AI features. Look for: user input concatenated directly into LLM prompts without sanitization, missing system prompt boundaries, tool/function calls executed without user confirmation, model outputs used in SQL/command/template rendering without validation, embedding search returning unauthorized content, RAG context leaking across users.' },
      { id: 'ai-output-safety', phase: 'integration', category: 'injection', description: 'Check AI output safety. Look for: LLM responses rendered as HTML without sanitization (XSS), model output used in database queries, AI-generated code executed without sandboxing, model hallucinations used for access control decisions, PII from training data leaked in responses, unlimited token generation (cost/DoS).' },
    ],
  },

  'proxy': {
    keywords: ['proxy', 'reverse proxy', 'api gateway', 'load balancer', 'ingress', 'edge'],
    knownDeps: ['http-proxy', 'http-proxy-middleware', 'express-http-proxy', '@fastify/http-proxy', 'redbird', 'node-http-proxy'],
    depSegments: ['proxy', 'gateway'],
    pathPatterns: [/proxy[/\\]/, /gateway[/\\]/],
    passes: [
      { id: 'proxy-ssrf', phase: 'integration', category: 'injection', description: 'Check for SSRF via proxy functionality. Look for: user-controlled URLs passed to proxy/fetch without allowlist, internal service URLs accessible via proxy endpoint, DNS rebinding attacks via proxy, HTTP header injection in proxied requests (CRLF), request smuggling via inconsistent parsing between proxy and backend.' },
    ],
  },

  'cron': {
    keywords: ['cron', 'scheduled', 'scheduler', 'periodic', 'timer', 'recurring task', 'background task'],
    knownDeps: ['node-cron', 'cron', 'node-schedule', 'agenda', 'bree', 'croner', 'toad-scheduler'],
    depSegments: ['cron', 'scheduler', 'schedule'],
    pathPatterns: [/cron[/\\]/, /schedulers?[/\\]/, /scheduled[/\\]/, /tasks?[/\\]/],
    passes: [
      { id: 'cron-safety', phase: 'unit', category: 'injection', description: 'Check scheduled task safety. Look for: cron job commands constructed from user input, scheduled tasks running with elevated privileges unnecessarily, cron schedule modifiable by non-admin users, missing locking for distributed cron (duplicate execution), long-running cron tasks without timeout, cron jobs accessing stale credentials/tokens.' },
    ],
  },

  'admin': {
    keywords: ['admin', 'backoffice', 'back-office', 'dashboard', 'management panel', 'control panel', 'superuser'],
    knownDeps: ['adminjs', '@adminjs/express', 'react-admin', 'ra-data-simple-rest'],
    depSegments: ['admin', 'backoffice', 'dashboard'],
    pathPatterns: [/admin[/\\]/, /backoffice[/\\]/, /dashboard[/\\]/, /panel[/\\]/],
    passes: [
      { id: 'privilege-boundary', phase: 'integration', category: 'auth-bypass', description: 'Verify admin privilege boundaries. Look for: admin endpoints accessible without role verification, admin actions not re-verified at service layer (only checked at route level), internal admin APIs callable from public network, admin impersonation feature without audit logging, admin tools exposing raw database queries.' },
    ],
  },

  'analytics': {
    keywords: ['analytics', 'tracking', 'metrics', 'telemetry', 'usage', 'event tracking'],
    knownDeps: ['mixpanel', 'segment', '@segment/analytics-node', 'posthog-js', 'posthog-node', 'amplitude-js', '@amplitude/analytics-node', 'plausible-tracker', 'umami'],
    depSegments: ['analytics', 'tracking', 'metrics', 'telemetry'],
    pathPatterns: [/analytics[/\\]/, /tracking[/\\]/, /metrics[/\\]/, /telemetry[/\\]/],
    passes: [
      { id: 'analytics-pii', phase: 'unit', category: 'secrets-exposure', description: 'Check for PII in analytics tracking. Look for: user email/name/IP sent to analytics services, session tokens or auth headers included in tracking events, form input values tracked without sanitization, URL parameters containing sensitive data sent to analytics, analytics scripts loading third-party code without integrity checks.' },
    ],
  },
};

// Critical domains that elevate hot path risk to "critical" when present
const CRITICAL_DOMAINS = new Set([
  'auth', 'session', 'oauth', 'access-control', 'mfa',
  'payments', 'crypto', 'multi-tenancy',
]);

// ─────────────────────────────────────────────────────────────
// Pass Skip Rules
// ─────────────────────────────────────────────────────────────

interface SkipRule {
  passName: string;
  condition: (ctx: SkipRuleContext) => boolean;
  reason: string;
}

interface SkipRuleContext {
  domains: string[];
  projectFiles: string[];
  deps: Record<string, string>;
  understanding: CodebaseUnderstanding;
}

const SKIP_RULES: SkipRule[] = [
  {
    passName: 'secrets-exposure',
    condition: (ctx) => {
      const hasEnvFiles = ctx.projectFiles.some(f => /\.env($|\.)/.test(f));
      const hasConfigFiles = ctx.projectFiles.some(f => /config\.(json|yml|yaml|toml)$/.test(f));
      return !hasEnvFiles && !hasConfigFiles;
    },
    reason: 'No env files or config files detected in project',
  },
  {
    passName: 'auth-bypass',
    condition: (ctx) => {
      return !hasAnyDomain(ctx.domains, ['auth', 'session', 'oauth', 'access-control', 'mfa']);
    },
    reason: 'No auth/session/access-control domain detected',
  },
  {
    passName: 'auth-flow-trace',
    condition: (ctx) => {
      return !hasAnyDomain(ctx.domains, ['auth', 'session', 'oauth', 'access-control', 'mfa']);
    },
    reason: 'No auth/session/access-control domain detected',
  },
  {
    passName: 'session-lifecycle-trace',
    condition: (ctx) => {
      return !hasAnyDomain(ctx.domains, ['session', 'auth', 'oauth']);
    },
    reason: 'No session/auth/oauth domain detected',
  },
  {
    passName: 'api-contract-verification',
    condition: (ctx) => {
      const hasOpenApi = ctx.projectFiles.some(f =>
        /openapi\.(json|yml|yaml)$/.test(f) ||
        /swagger\.(json|yml|yaml)$/.test(f) ||
        /api-spec\.(json|yml|yaml)$/.test(f)
      );
      return !hasOpenApi;
    },
    reason: 'No OpenAPI/Swagger specification files detected',
  },
];

function hasAnyDomain(detected: string[], needed: string[]): boolean {
  return needed.some(d => detected.includes(d));
}

// ─────────────────────────────────────────────────────────────
// Sensitive Data Detection
// ─────────────────────────────────────────────────────────────

interface SensitiveDataPattern {
  type: string;
  keywords: string[];
  domainIndicators: string[];
}

const SENSITIVE_DATA_PATTERNS: SensitiveDataPattern[] = [
  { type: 'PII', keywords: ['email', 'phone', 'address', 'name', 'ssn', 'social security', 'date of birth', 'national id'], domainIndicators: ['analytics'] },
  { type: 'financial', keywords: ['credit card', 'bank', 'account number', 'routing', 'payment', 'transaction', 'balance', 'billing'], domainIndicators: ['payments', 'e-commerce', 'subscription'] },
  { type: 'health', keywords: ['medical', 'health', 'patient', 'diagnosis', 'prescription', 'hipaa', 'ehr', 'clinical'], domainIndicators: [] },
  { type: 'credentials', keywords: ['password', 'api key', 'secret key', 'credential', 'access key', 'private key'], domainIndicators: ['auth', 'crypto', 'config'] },
  { type: 'authentication-tokens', keywords: ['token', 'jwt', 'session id', 'bearer', 'refresh token', 'oauth token'], domainIndicators: ['session', 'oauth'] },
  { type: 'location', keywords: ['gps', 'latitude', 'longitude', 'geolocation', 'location tracking', 'coordinates'], domainIndicators: [] },
  { type: 'biometric', keywords: ['fingerprint', 'face id', 'biometric', 'retina', 'voice print'], domainIndicators: ['mfa'] },
  { type: 'legal', keywords: ['gdpr', 'ccpa', 'compliance', 'consent', 'data retention', 'right to deletion', 'dpa'], domainIndicators: [] },
];

// ─────────────────────────────────────────────────────────────
// Core Risk Profiler
// ─────────────────────────────────────────────────────────────

export function generateRiskProfile(
  understanding: CodebaseUnderstanding,
  projectFiles: string[],
  packageJsonDeps?: Record<string, string>,
): RiskProfile {
  const deps = packageJsonDeps || understanding.dependencies || {};
  const descriptionLower = understanding.summary.description.toLowerCase();
  const featureNames = understanding.features.map(f => f.name.toLowerCase());
  const featureDescriptions = understanding.features.map(f => f.description.toLowerCase());
  const relatedFiles = understanding.features.flatMap(f => f.relatedFiles || []);

  // 1. Detect domains
  const domains = detectDomains(descriptionLower, featureNames, featureDescriptions, deps, projectFiles, relatedFiles);

  // 2. Detect sensitive data types
  const sensitiveDataTypes = detectSensitiveData(descriptionLower, featureDescriptions, domains);

  // 3. Detect external dependencies (non-dev, non-trivial)
  const externalDependencies = Object.keys(deps).filter(dep =>
    !dep.startsWith('@types/') && !dep.startsWith('eslint') && !dep.startsWith('vitest') &&
    !dep.startsWith('typescript') && !dep.startsWith('prettier')
  );

  // 4. Detect hot paths
  const hotPaths = detectHotPaths(projectFiles, relatedFiles, domains);

  // 5. Generate custom passes
  const customPasses = generateCustomPasses(domains);

  // 6. Determine skipped passes
  const skippedPasses = determineSkippedPasses({
    domains,
    projectFiles,
    deps,
    understanding,
  });

  return {
    version: '1',
    generatedAt: new Date().toISOString(),
    domains,
    sensitiveDataTypes,
    externalDependencies,
    hotPaths,
    customPasses,
    skippedPasses,
  };
}

// ─────────────────────────────────────────────────────────────
// Internal Functions
// ─────────────────────────────────────────────────────────────

/**
 * Check if a keyword appears as a whole word or word-prefix in text.
 * Short keywords (<=3 chars) use exact word boundary on both sides to prevent
 * false positives like "ai" matching "airports" or "log" matching "logistics".
 * Longer keywords use word boundary on the left only (prefix matching), so:
 * - "auth" matches "auth", "authentication", "authorize" (word-start match)
 * - "orm" matches "orm setup" but NOT "formatting" (not at word start)
 * - "api" matches "api endpoints" but NOT "capital" (not at word start)
 * - "ai" matches "ai model" but NOT "airports" (exact word for short keywords)
 * - "log" matches "log aggregation" but NOT "logistics" (exact word for short keywords)
 */
function matchesKeyword(text: string, keyword: string): boolean {
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Short keywords: require exact word match (boundary on both sides)
  if (keyword.length <= 3) {
    return new RegExp(`\\b${escaped}\\b`, 'i').test(text);
  }
  return new RegExp(`\\b${escaped}`, 'i').test(text);
}

/**
 * Split a dependency name into segments for generic matching.
 * "@aws-sdk/client-s3" -> ["aws", "sdk", "client", "s3"]
 * "express-rate-limit" -> ["express", "rate", "limit"]
 */
function depNameSegments(depName: string): string[] {
  return depName
    .replace(/^@/, '')
    .split(/[-/._]/)
    .filter(s => s.length > 1)
    .map(s => s.toLowerCase());
}

function detectDomains(
  descriptionLower: string,
  featureNames: string[],
  featureDescriptions: string[],
  deps: Record<string, string>,
  projectFiles: string[],
  relatedFiles: string[],
): string[] {
  const detected = new Set<string>();
  const depNames = Object.keys(deps);
  // Pre-compute dep segments once
  const allDepSegments = depNames.flatMap(d => depNameSegments(d));
  const allFeatureText = [...featureNames, ...featureDescriptions];
  const allFiles = [...projectFiles, ...relatedFiles];

  for (const [domain, def] of Object.entries(DOMAINS)) {
    // 1. Check description keywords (word-boundary match)
    if (def.keywords.some(kw => matchesKeyword(descriptionLower, kw))) {
      detected.add(domain);
      continue;
    }

    // 2. Check feature names and descriptions (word-boundary match)
    if (def.keywords.some(kw => allFeatureText.some(ft => matchesKeyword(ft, kw)))) {
      detected.add(domain);
      continue;
    }

    // 3. Check known dependency names (exact match)
    if (def.knownDeps.some(dep => depNames.includes(dep))) {
      detected.add(domain);
      continue;
    }

    // 4. Check dep name segments (generic capability detection)
    if (def.depSegments.length > 0 && def.depSegments.some(seg => allDepSegments.includes(seg))) {
      detected.add(domain);
      continue;
    }

    // 5. Check file paths
    if (def.pathPatterns.length > 0 && def.pathPatterns.some(pattern => allFiles.some(f => pattern.test(f)))) {
      detected.add(domain);
      continue;
    }
  }

  return Array.from(detected).sort();
}

function detectSensitiveData(
  descriptionLower: string,
  featureDescriptions: string[],
  domains: string[],
): string[] {
  const detected = new Set<string>();
  const allText = [descriptionLower, ...featureDescriptions].join(' ');

  for (const pattern of SENSITIVE_DATA_PATTERNS) {
    if (pattern.keywords.some(kw => matchesKeyword(allText, kw))) {
      detected.add(pattern.type);
    }
    if (pattern.domainIndicators.some(d => domains.includes(d))) {
      detected.add(pattern.type);
    }
  }

  return Array.from(detected).sort();
}

function detectHotPaths(
  projectFiles: string[],
  relatedFiles: string[],
  domains: string[],
): HotPath[] {
  const hotPaths: HotPath[] = [];
  const allFiles = [...new Set([...projectFiles, ...relatedFiles])];

  for (const file of allFiles) {
    const touchedDomains: string[] = [];

    for (const [domain, def] of Object.entries(DOMAINS)) {
      if (!domains.includes(domain)) continue;
      if (def.pathPatterns.length === 0) continue;

      if (def.pathPatterns.some(pattern => pattern.test(file))) {
        touchedDomains.push(domain);
      }
    }

    // A hot path touches 2+ sensitive domains
    if (touchedDomains.length >= 2) {
      const riskLevel = touchedDomains.some(d => CRITICAL_DOMAINS.has(d)) ? 'critical' : 'high';
      hotPaths.push({
        file,
        reason: `Touches ${touchedDomains.join(' + ')} domains`,
        riskLevel,
      });
    }
  }

  return hotPaths;
}

function generateCustomPasses(domains: string[]): CustomPassConfig[] {
  const passes: CustomPassConfig[] = [];

  for (const domain of domains) {
    const def = DOMAINS[domain];
    if (def && def.passes.length > 0) {
      passes.push(...def.passes);
    }
  }

  return passes;
}

function determineSkippedPasses(ctx: SkipRuleContext): SkipReason[] {
  const skipped: SkipReason[] = [];

  for (const rule of SKIP_RULES) {
    if (rule.condition(ctx)) {
      skipped.push({
        passName: rule.passName,
        reason: rule.reason,
      });
    }
  }

  return skipped;
}
