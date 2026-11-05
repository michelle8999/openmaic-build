/**
 * 向 OpenMAIC/instrumentation.ts 的 register() 注入 owner auth 注册代码。
 * 在服务器上通过 node 容器执行（服务器无需安装 node）：
 *   docker run --rm -v "$PWD:/w" -w /w node:20-alpine node /w/patch-instrumentation.js /w/OpenMAIC
 * 幂等：已打过补丁会跳过；找不到锚点会报错退出。
 */
'use strict';
const fs = require('fs');
const path = require('path');

const repoDir = process.argv[2] || '/w/OpenMAIC';
const file = path.join(repoDir, 'instrumentation.ts');
const MARK = 'openmaic-deploy: gatewayJwtMethod';
const ANCHOR = "if (process.env.NEXT_RUNTIME !== 'nodejs') return;";

let src = fs.readFileSync(file, 'utf8');
if (src.includes(MARK)) {
  console.log('[patch] already applied, skip');
  process.exit(0);
}
const idx = src.indexOf(ANCHOR);
if (idx === -1) {
  console.error('[patch] anchor not found: ' + ANCHOR);
  process.exit(1);
}
const insertAt = idx + ANCHOR.length;
const patch = `

  // --- ${MARK} ---
  // 注册登录网关签发的 HS256 JWT 认证方法；anonymousFallback:false = 必须登录。
  // 必须在 validateBootConfiguration() 之前注册（官方约定）。
  {
    const { configureOwnerAuthentication } = await import('@/lib/server/identity');
    const { gatewayJwtMethod } = await import('@/lib/server/identity/host/gateway-jwt');
    configureOwnerAuthentication({ methods: [gatewayJwtMethod], anonymousFallback: false });
  }
  // --- end ${MARK} ---`;
src = src.slice(0, insertAt) + patch + src.slice(insertAt);
fs.writeFileSync(file, src);
console.log('[patch] instrumentation.ts patched OK');
