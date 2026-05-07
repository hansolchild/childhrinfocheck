// =============================================================
// functions/api/[[path]].js
// Cloudflare Pages Function — GAS REST API 프록시
//
// 역할:
//   1. GAS 배포 URL을 환경변수(GAS_URL)에 은닉
//   2. 클라이언트 ↔ Worker 간 PSK(X-Hansol-Key) 검증
//   3. Worker ↔ GAS 간 동일 PSK를 body._psk 로 전달
//   4. CORS / 보안 헤더 일괄 적용
//
// Cloudflare Pages 환경변수 (대시보드 → Settings → Environment Variables):
//   GAS_URL        : https://script.google.com/macros/s/AKfy.../exec
//   HANSOL_PSK     : (32자 이상 랜덤 문자열, 클라이언트 JS에도 동일 값 설정)
//   ALLOWED_ORIGIN : https://your-project.pages.dev  (또는 커스텀 도메인)
// =============================================================

export async function onRequestPost(context) {
  const { request, env } = context;

  // ── CORS Preflight ─────────────────────────────────────────
  if (request.method === 'OPTIONS') {
    return corsResponse(null, 204, env);
  }

  // ── 1. PSK 검증 ────────────────────────────────────────────
  const clientPSK = request.headers.get('X-Hansol-Key') || '';
  if (env.HANSOL_PSK && clientPSK !== env.HANSOL_PSK) {
    return corsResponse(
      JSON.stringify({ success: false, error: 'Unauthorized' }),
      401, env
    );
  }

  // ── 2. 요청 바디 파싱 ──────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return corsResponse(
      JSON.stringify({ success: false, error: 'Invalid JSON body' }),
      400, env
    );
  }

  // ── 3. GAS URL 검증 ────────────────────────────────────────
  const gasUrl = env.GAS_URL;
  if (!gasUrl) {
    return corsResponse(
      JSON.stringify({ success: false, error: 'GAS_URL not configured' }),
      500, env
    );
  }

  // ── 4. GAS로 요청 전달 (PSK를 body에 포함) ────────────────
  // GAS는 헤더를 읽지 못하므로 body._psk 로 전달
  const gasBody = { ...body, _psk: env.HANSOL_PSK };

  let gasRes;
  try {
    gasRes = await fetch(gasUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(gasBody),
      // Cloudflare가 GAS 리다이렉트(302)를 자동 추적
      redirect: 'follow',
    });
  } catch (e) {
    return corsResponse(
      JSON.stringify({ success: false, error: 'GAS unreachable: ' + e.message }),
      502, env
    );
  }

  // ── 5. GAS 응답 그대로 클라이언트에 전달 ──────────────────
  const gasData = await gasRes.text();
  return corsResponse(gasData, gasRes.status, env);
}

// OPTIONS(Preflight) 허용
export async function onRequestOptions(context) {
  return corsResponse(null, 204, context.env);
}

// ── CORS + 보안헤더 래퍼 ──────────────────────────────────────
function corsResponse(body, status, env) {
  const origin = env.ALLOWED_ORIGIN || '*';
  const headers = {
    'Content-Type':                'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods':'POST, OPTIONS',
    'Access-Control-Allow-Headers':'Content-Type, X-Hansol-Key',
    'Access-Control-Max-Age':      '86400',
    // 보안 헤더
    'X-Content-Type-Options':      'nosniff',
    'X-Frame-Options':             'DENY',
    'Referrer-Policy':             'strict-origin-when-cross-origin',
    'Cache-Control':               'no-store',
  };
  return new Response(body, { status: status || 200, headers });
}
