import dotenv from 'dotenv';

dotenv.config();

export interface BackendConfig {
  port: number;
  host: string;
  nodeEnv: string;
  corsOrigin: string;
  databaseUrl: string;
  jwtSecret: string;
  jwtExpiresIn: string;
  bcryptSaltRounds: number;
}

export function getConfig(): BackendConfig {
  const port = parseInt(process.env.PORT || '4000', 10);
  const host = process.env.HOST || '0.0.0.0';
  const nodeEnv = process.env.NODE_ENV || 'development';
  const corsOrigin = process.env.CORS_ORIGIN || '*';
  const databaseUrl =
    process.env.DATABASE_URL ||
    'postgresql://deception_user:deception_pass@localhost:5432/deception_db';

  // Secure token secret: in production, must be supplied via environment variable
  const jwtSecret =
    process.env.OPERATOR_JWT_SECRET ||
    process.env.JWT_SECRET ||
    'deception-gateway-operator-secret-key-32chars-min!';

  const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '8h';
  const bcryptSaltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);

  return {
    port,
    host,
    nodeEnv,
    corsOrigin,
    databaseUrl,
    jwtSecret,
    jwtExpiresIn,
    bcryptSaltRounds,
  };
}
