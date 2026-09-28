import { createApp } from './app.ts';
import { env } from './config/env.ts';
import { db } from './db/database.ts';

const server = createApp().listen(env.PORT, () => {
  console.log(`API listening on http://localhost:${env.PORT} (${env.NODE_ENV})`);
});

// Housekeeping: purge long-dead sessions and tokens so tables don't grow forever.
const purge = setInterval(() => {
  const cutoff = Date.now() - 30 * 24 * 3600_000;
  db.prepare('DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR absolute_expires_at < ?').run(cutoff, Date.now());
  db.prepare('DELETE FROM one_time_tokens WHERE expires_at < ?').run(cutoff);
}, 3600_000);
purge.unref();

function shutdown(signal: string) {
  console.log(`${signal} received, shutting down`);
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
