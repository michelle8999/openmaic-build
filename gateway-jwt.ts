/**
 * OpenMAIC host auth method: verify gateway-signed HS256 JWT.
 *
 * 放置位置（官方约定）：lib/server/identity/host/gateway-jwt.ts
 * 由 instrumentation.ts 的 register() 调用 configureOwnerAuthentication 注册。
 *
 * 与官方 "signed-JWT gateway recipe" 的差异：官方示例面向 oauth2-proxy /
 * Cloudflare Access 等 IdP（RS256/ES256 + JWKS 远程公钥）。本部署的 JWT 由
 * 我们自建的登录网关用共享密钥 HS256 签发，故用 Web Crypto（Node 内建，
 * 零新增依赖）做 HMAC-SHA256 验签，issuer/audience/algorithms 全部固定。
 */
import type { OwnerAuthMethod } from '@/lib/server/identity';

const ISSUER = 'openmaic-gateway';
const AUDIENCE = 'openmaic';
const ALG = 'HS256';
const CLOCK_TOLERANCE_SECONDS = 30;

const secret = new TextEncoder().encode(process.env.GATEWAY_JWT_SECRET ?? '');
if (secret.length < 32) {
  // 密钥缺失/过短属于部署错误：让进程在 boot 时显式失败，而不是默默放行。
  throw new Error(
    '[gateway-jwt] GATEWAY_JWT_SECRET is missing or shorter than 32 characters',
  );
}

function base64UrlDecode(part: string): Uint8Array<ArrayBuffer> {
  const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

class TokenError extends Error {}

async function verifyGatewayJwt(
  token: string,
): Promise<Record<string, unknown>> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new TokenError('malformed jwt');
  const [head, body, sig] = parts;

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(head)));
  } catch {
    throw new TokenError('malformed header');
  }
  if (header.alg !== ALG || header.typ !== 'JWT') {
    throw new TokenError('unacceptable alg or typ');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const data = new TextEncoder().encode(`${head}.${body}`);
  const signature = base64UrlDecode(sig);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new TokenError('bad signature');

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body)));
  } catch {
    throw new TokenError('malformed payload');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now - CLOCK_TOLERANCE_SECONDS) {
    throw new TokenError('expired');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now + CLOCK_TOLERANCE_SECONDS) {
    throw new TokenError('not yet valid');
  }
  if (payload.iss !== ISSUER) throw new TokenError('wrong issuer');
  const aud = payload.aud;
  const audienceOk = aud === AUDIENCE || (Array.isArray(aud) && aud.includes(AUDIENCE));
  if (!audienceOk) throw new TokenError('wrong audience');

  return payload;
}

function bearerToken(headers: Headers): string | undefined {
  const match = /^Bearer\s+(\S+)$/i.exec(headers.get('authorization')?.trim() ?? '');
  return match?.[1];
}

export const gatewayJwtMethod: OwnerAuthMethod = {
  name: 'gatewayJwt',
  async authenticate(req) {
    const token = bearerToken(req.headers);
    // 没有 header 才是 not-applicable；有但坏是 invalid（官方铁律）。
    if (token === undefined) return { status: 'not-applicable' };
    let payload: Record<string, unknown>;
    try {
      payload = await verifyGatewayJwt(token);
    } catch (error) {
      if (error instanceof TokenError) return { status: 'invalid', reason: error.message };
      throw error; // 密钥材料异常等属于服务器故障，按 500 处理
    }
    const sub = typeof payload.sub === 'string' ? payload.sub : '';
    const ownerId = `user:${sub}`;
    if (!sub || !/^[\x21-\x7e]{1,256}$/.test(ownerId)) {
      return { status: 'invalid', reason: 'unusable sub' };
    }
    const role = payload.role === 'admin' ? 'admin' : 'course:publish';
    const roles = new Set<string>(['course:publish']);
    if (role === 'admin') roles.add('admin');
    const name = typeof payload.name === 'string' ? payload.name : undefined;
    return {
      status: 'authenticated',
      principal: {
        ownerId,
        kind: 'user',
        roles,
        assurance: 'verified',
        channel: 'gateway',
        ...(name ? { displayName: name } : {}),
      },
    };
  },
  describeStoredOwner: (ownerId) =>
    ownerId.startsWith('user:')
      ? { kind: 'user', roles: new Set(['course:publish']) }
      : undefined,
};
