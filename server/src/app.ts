import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { env } from './config/env.ts';
import { errorHandler, notFoundHandler } from './middleware/errors.ts';
import { CSRF_HEADER, globalLimiter } from './middleware/security.ts';
import { articlesRouter } from './modules/articles/articles.routes.ts';
import { auditRouter } from './modules/audit/audit.routes.ts';
import { authRouter } from './modules/auth/auth.routes.ts';
import { rolesRouter } from './modules/roles/roles.routes.ts';
import { usersRouter } from './modules/users/users.routes.ts';
import { syncRbacCatalog } from './rbac/rbac.service.ts';

export function createApp() {
  syncRbacCatalog();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', env.TRUST_PROXY);

  app.use(helmet());
  app.use(cors({
    origin: (origin, cb) => cb(null, !origin || env.CORS_ORIGINS.includes(origin)),
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', CSRF_HEADER],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    maxAge: 600,
  }));
  app.use(express.json({ limit: '100kb' }));
  app.use(cookieParser());
  app.use('/api', globalLimiter);
  // Authenticated responses must never be cached by browsers or intermediaries.
  app.use('/api', (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.use('/api/auth', authRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/roles', rolesRouter);
  app.use('/api/articles', articlesRouter);
  app.use('/api/audit', auditRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
