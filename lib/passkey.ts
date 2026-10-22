import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
type Row = Record<string, any>;
const SESSION = '__Host-t08_session', BINDING = '__Host-t08_binding';
const b64 = (v: Uint8Array) => btoa(String.fromCharCode(...v)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
async function hash(s: string) { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))); }
function cookie(req: Request, name: string) { return req.headers.get('cookie')?.split(';').map(v => v.trim()).find(v => v.startsWith(name + '='))?.slice(name.length + 1) || ''; }
function setCookie(name: string, value: string, age = 3600) { return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${age}`; }
function json(data: unknown, status = 200, cookies: string[] = []) {
  const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', Vary: 'Cookie' });
  cookies.forEach(c => headers.append('Set-Cookie', c));
  return new Response(JSON.stringify(data), { status, headers });
}
class Denied extends Error { constructor(public status: number, public code: string) { super(code); } }
function deny(code: string, status = 403): never { throw new Denied(status, code); }
async function session(req: Request, db: D1Database) {
  const raw = cookie(req, SESSION); if (!raw) deny('login_required', 401);
  const s = await db.prepare('SELECT * FROM sessions WHERE hash = ? AND expires_at > ?').bind(await hash(raw), Date.now()).first<Row>();
  if (!s) deny('session_expired_or_revoked', 401); return s;
}
async function log(db: D1Database, owner: string, event: string, detail: unknown) {
  await db.prepare('INSERT INTO audit (id, owner, event, detail, created_at) VALUES (?, ?, ?, ?, ?)').bind(crypto.randomUUID(), owner, event, JSON.stringify(detail), Date.now()).run();
}
async function newSession(db: D1Database, owner: string) {
  const token = random();
  await db.prepare('INSERT INTO sessions (hash, owner, expires_at) VALUES (?, ?, ?)').bind(await hash(token), owner, Date.now() + 3600000).run();
  return setCookie(SESSION, token);
}
async function issue(req: Request, db: D1Database, data: Row) {
  const binding = cookie(req, BINDING) || random(), ticket = random();
  await db.prepare('DELETE FROM challenges WHERE expires_at < ?').bind(Date.now()).run();
  await db.prepare('INSERT INTO challenges (id, challenge, kind, owner, binding, session_hash, name, provider, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(ticket, data.challenge, data.kind, data.owner, await hash(binding), data.session_hash, data.name, data.provider, Date.now() + 120000).run();
  return { ticket, cookie: setCookie(BINDING, binding) };
}
async function consume(req: Request, db: D1Database, ticket: unknown, kind: string) {
  if (typeof ticket !== 'string' || !cookie(req, BINDING)) deny('challenge_missing');
  // DELETE RETURNING consumes a question atomically before signature verification.
  const q = await db.prepare('DELETE FROM challenges WHERE id = ? AND binding = ? AND kind = ? RETURNING *').bind(ticket, await hash(cookie(req, BINDING)), kind).first<Row>();
  if (!q) deny('challenge_used_or_unknown'); if (q.expires_at <= Date.now()) deny('challenge_expired');
  if (q.session_hash) { const s = await session(req, db); if (s.hash !== q.session_hash || s.owner !== q.owner) deny('registration_session_changed'); }
  return q;
}
const providers = ['Google 비밀번호 관리자', '기기 자체', '보안 키', '기타 / 확인 필요'];
export async function handlePasskey(req: Request, db: D1Database, trustedOrigin: string): Promise<Response> {
  const url = new URL(req.url), rpID = new URL(trustedOrigin).hostname, path = url.pathname.replace(/\/$/, '');
  let ownerForFailure = '';
  try {
    if (url.origin !== trustedOrigin) deny('unexpected_origin');
    if (!['GET', 'POST', 'DELETE'].includes(req.method)) deny('method_not_allowed', 405);
    if (req.method !== 'GET') {
      if (req.headers.get('origin') !== trustedOrigin) deny('cross_origin_request');
      if (req.headers.get('content-type')?.split(';')[0] !== 'application/json') deny('json_required', 415);
    }
    if (req.method === 'GET' && path === '/api/auth/session') {
      try { const s = await session(req, db); return json({ authenticated: true, accountId: s.owner }); }
      catch (e) { if (e instanceof Denied) return json({ authenticated: false }); throw e; }
    }
    if (req.method === 'GET' && path === '/api/private') {
      const s = await session(req, db); ownerForFailure = s.owner;
      if (url.searchParams.has('accountId') && url.searchParams.get('accountId') !== s.owner) deny('owner_mismatch');
      const result = await db.prepare('SELECT id, title, content FROM notes WHERE owner = ? ORDER BY id').bind(s.owner).all();
      return json({ accountId: s.owner, items: result.results });
    }
    if (req.method === 'GET' && path === '/api/passkeys') {
      const s = await session(req, db);
      const result = await db.prepare('SELECT id, name, provider, created_at, public_key, device_type, backed_up FROM credentials WHERE owner = ? ORDER BY created_at').bind(s.owner).all();
      return json({ accountId: s.owner, items: result.results, storedKeyType: 'COSE 공개키 (Base64URL). 비밀번호·개인키는 저장하지 않음.' });
    }
    if (req.method === 'GET' && path === '/api/evidence') {
      const s = await session(req, db);
      const result = await db.prepare('SELECT event, detail, created_at FROM audit WHERE owner = ? ORDER BY created_at DESC LIMIT 150').bind(s.owner).all();
      return json({ accountId: s.owner, records: result.results, secretValues: '[REDACTED]', note: '세션·쿠키·개인키·비공개 본문은 기록하지 않습니다.' });
    }
    const rawBody = await req.text(); if (rawBody.length > 64000) deny('request_too_large', 413);
    let body: any; try { body = JSON.parse(rawBody); } catch { deny('invalid_json', 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) deny('invalid_json', 400);
    if (req.method === 'POST' && path === '/api/private') {
      const s = await session(req, db);
      // Ignore client-claimed accountId. The verified session is the only owner source.
      const result = await db.prepare('SELECT id, title, content FROM notes WHERE owner = ? ORDER BY id').bind(s.owner).all();
      await log(db, s.owner, 'body_owner_ignored', { requestedAccountId: body.accountId || null, returnedAccountId: s.owner, count: result.results.length, status: 200 });
      return json({ accountId: s.owner, items: result.results });
    }
    if (req.method === 'POST' && path === '/api/auth/register/options') {
      const s = cookie(req, SESSION) ? await session(req, db) : null; ownerForFailure = s?.owner || '';
      const owner = s?.owner || random(), name = String(body.name || '').trim().slice(0, 40), provider = String(body.provider || '');
      if (!name || !providers.includes(provider)) deny('name_and_provider_required', 400);
      const existing = await db.prepare('SELECT id, transports FROM credentials WHERE owner = ?').bind(owner).all<Row>();
      if (existing.results.length >= 8) deny('passkey_limit', 400);
      const options = await generateRegistrationOptions({ rpName: 'YC 소개 · 개인 공간', rpID, userID: bytes(owner), userName: `학습계정-${owner.slice(0, 8)}`, userDisplayName: '개인 학습 공간', attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, excludeCredentials: existing.results.map(c => ({ id: c.id, transports: JSON.parse(c.transports) })) });
      const q = await issue(req, db, { challenge: options.challenge, kind: 'register', owner, session_hash: s?.hash || null, name, provider });
      return json({ options, ticket: q.ticket, expiresInSeconds: 120 }, 200, [q.cookie]);
    }
    if (req.method === 'POST' && path === '/api/auth/register/verify') {
      const q = await consume(req, db, body.ticket, 'register'); ownerForFailure = q.owner;
      const v = await verifyRegistrationResponse({ response: body.response, expectedChallenge: q.challenge, expectedOrigin: trustedOrigin, expectedRPID: rpID, requireUserVerification: true });
      if (!v.verified || !v.registrationInfo) deny('registration_signature_invalid');
      const { credential, credentialDeviceType, credentialBackedUp } = v.registrationInfo;
      const exists = await db.prepare('SELECT id FROM accounts WHERE id = ?').bind(q.owner).first();
      const statements = [];
      if (!exists) {
        statements.push(db.prepare('INSERT INTO accounts (id, created_at) VALUES (?, ?)').bind(q.owner, Date.now()));
        const seed = [['프로젝트 준비 메모', `가상 실습 ${q.owner.slice(0,6)}: 방화벽 허용 정책을 정리하고 통신 결과를 비교한다.`], ['지원 계획 연습', `가상 기업 ${q.owner.slice(0,6)}: 보안 솔루션 엔지니어 역할을 조사한다. 실제 지원 정보가 아니다.`], ['나만의 학습 회고', `가상 회고 ${q.owner.slice(0,6)}: 설정을 바꾸기 전에 원인을 확인하고 결과를 기록한다.`]];
        for (const [title, content] of seed) statements.push(db.prepare('INSERT INTO notes (id, owner, title, content) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), q.owner, title, content));
      }
      statements.push(db.prepare('INSERT INTO credentials (id, owner, public_key, counter, transports, name, provider, device_type, backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(credential.id, q.owner, b64(credential.publicKey), credential.counter, JSON.stringify(credential.transports || []), q.name, q.provider, credentialDeviceType, credentialBackedUp ? 1 : 0, Date.now()));
      await db.batch(statements);
      await log(db, q.owner, 'registration_success', { request: body.response, challenge: q.challenge, response: { status: 200, verified: true }, stored: { id: credential.id, publicKey: b64(credential.publicKey), type: 'COSE public key', name: q.name, provider: q.provider }, privateKeyTransmitted: false, providerIsUserDeclared: true });
      return json({ verified: true, accountId: q.owner, credentialId: credential.id }, 200, [await newSession(db, q.owner)]);
    }
    if (req.method === 'POST' && path === '/api/auth/login/options') {
      const options = await generateAuthenticationOptions({ rpID, userVerification: 'required' });
      const q = await issue(req, db, { challenge: options.challenge, kind: 'login', owner: '', session_hash: null, name: '', provider: '' });
      return json({ options, ticket: q.ticket, expiresInSeconds: 120 }, 200, [q.cookie]);
    }
    if (req.method === 'POST' && path === '/api/auth/login/verify') {
      const q = await consume(req, db, body.ticket, 'login');
      const c = await db.prepare('SELECT * FROM credentials WHERE id = ?').bind(String(body.response?.id || '')).first<Row>();
      if (!c) deny('passkey_unknown_or_deleted'); ownerForFailure = c.owner;
      if (body.response.response.userHandle && body.response.response.userHandle !== c.owner) deny('user_handle_mismatch');
      const v = await verifyAuthenticationResponse({ response: body.response, expectedChallenge: q.challenge, expectedOrigin: trustedOrigin, expectedRPID: rpID, credential: { id: c.id, publicKey: bytes(c.public_key), counter: c.counter, transports: JSON.parse(c.transports) }, requireUserVerification: true });
      if (!v.verified) deny('login_signature_invalid');
      const updated = await db.prepare('UPDATE credentials SET counter = ? WHERE id = ? AND counter = ? RETURNING id').bind(v.authenticationInfo.newCounter, c.id, c.counter).first();
      if (!updated) deny('credential_changed');
      const previous = cookie(req, SESSION); if (previous) await db.prepare('DELETE FROM sessions WHERE hash = ?').bind(await hash(previous)).run();
      await log(db, c.owner, 'login_success', { challenge: q.challenge, request: body.response, response: { status: 200, verified: true }, session: '[REDACTED]' });
      return json({ verified: true, accountId: c.owner }, 200, [await newSession(db, c.owner)]);
    }
    if (req.method === 'POST' && path === '/api/auth/cancel') {
      if (cookie(req, BINDING) && typeof body.ticket === 'string') await db.prepare('DELETE FROM challenges WHERE id = ? AND binding = ?').bind(body.ticket, await hash(cookie(req, BINDING))).run();
      return json({ cancelled: true, credentialSaved: false });
    }
    if (req.method === 'POST' && path === '/api/auth/logout') {
      const s = await session(req, db); await db.prepare('DELETE FROM sessions WHERE hash = ?').bind(s.hash).run();
      await log(db, s.owner, 'logout', { status: 200, session: '[REDACTED]', revokedOnServer: true });
      return json({ loggedOut: true }, 200, [setCookie(SESSION, '', 0)]);
    }
    if (req.method === 'DELETE' && path === '/api/passkeys') {
      const s = await session(req, db); ownerForFailure = s.owner;
      const removed = await db.prepare('DELETE FROM credentials WHERE id = ? AND owner = ? RETURNING id').bind(String(body.id || ''), s.owner).first();
      if (!removed) deny('passkey_not_owned');
      const remaining = await db.prepare('SELECT COUNT(*) AS count FROM credentials WHERE owner = ?').bind(s.owner).first<Row>();
      const count = remaining!.count;
      await log(db, s.owner, 'passkey_deleted', { credentialId: body.id, remaining: count, status: 200 });
      if (count === 0) {
        await db.batch([db.prepare('DELETE FROM sessions WHERE owner = ?').bind(s.owner), db.prepare('DELETE FROM challenges WHERE owner = ?').bind(s.owner)]);
        return json({ deleted: true, remaining: 0, lockedOut: true, message: '패스키가 하나도 없습니다. 기존 공간으로 다시 로그인할 수 없으며 복구 수단도 없습니다.' }, 200, [setCookie(SESSION, '', 0)]);
      }
      return json({ deleted: true, remaining: count });
    }
    return json({ error: 'not_found' }, 404);
  } catch (e) {
    const status = e instanceof Denied ? e.status : 403, code = e instanceof Denied ? e.code : 'verification_failed';
    if (ownerForFailure) await log(db, ownerForFailure, 'request_denied', { path, status, error: code });
    return json({ error: code, message: '인증 또는 권한 확인에 실패했습니다. 새 질문을 받아 다시 시도하세요.' }, status);
  }
}
