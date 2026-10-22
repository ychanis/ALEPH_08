import { env } from 'cloudflare:workers';
import { handlePasskey } from '@/lib/passkey';
export const dynamic = 'force-dynamic';
const ORIGIN = 'https://yc-aleph-08-passkey.ksyji123.chatgpt.site';
async function handle(req: Request) {
  if (!env.DB) return Response.json({ error: 'database_unavailable' }, { status: 503 });
  return handlePasskey(req, env.DB, ORIGIN);
}
export const GET = handle;
export const POST = handle;
export const DELETE = handle;
