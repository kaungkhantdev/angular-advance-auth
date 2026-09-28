import { z } from 'zod';

/**
 * Configuration is validated once at startup (fail fast). Anything security
 * relevant must be explicit — there are no silent insecure defaults in production.
 */
const secret = z
  .string()
  .min(32, 'must be at least 32 characters')
  .refine((s) => !s.startsWith('change-me'), 'placeholder secret — generate a real one');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  /** Number of reverse-proxy hops in front of the app (for correct client IPs). 0 = none. */
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),
  CORS_ORIGINS: z
    .string()
    .default('http://localhost:4200')
    .transform((s) => s.split(',').map((o) => o.trim()).filter(Boolean)),
  DATABASE_PATH: z.string().default('./data/auth.db'),
  JWT_ACCESS_SECRET: secret,
  JWT_MFA_SECRET: secret,
  /** 32-byte key (base64url) used for AES-256-GCM encryption of TOTP secrets at rest. */
  DATA_ENCRYPTION_KEY: z
    .string()
    .refine((s) => Buffer.from(s, 'base64url').length === 32, 'must be 32 random bytes, base64url-encoded'),
  JWT_ISSUER: z.string().default('advance-auth'),
  JWT_AUDIENCE: z.string().default('advance-auth-web'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(7 * 24 * 3600),
  SESSION_ABSOLUTE_TTL_SECONDS: z.coerce.number().int().positive().default(30 * 24 * 3600),
  APP_URL: z.url().default('http://localhost:4200'),
  SEED_ADMIN_EMAIL: z.email().optional(),
  SEED_ADMIN_PASSWORD: z.string().optional(),
});

export type Env = z.infer<typeof schema>;

function load(): Env {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    console.error(`Invalid environment configuration:\n${issues}`);
    process.exit(1);
  }
  if (parsed.data.JWT_ACCESS_SECRET === parsed.data.JWT_MFA_SECRET) {
    console.error('JWT_ACCESS_SECRET and JWT_MFA_SECRET must differ (key separation).');
    process.exit(1);
  }
  return parsed.data;
}

export const env = load();
export const isProd = env.NODE_ENV === 'production';
