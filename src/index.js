import {
  constantTimeEqual,
  createSession,
  decryptText,
  encryptText,
  normalizeSecret,
  sha256,
  totp,
  verifySession,
} from "./crypto.js";

const COOKIE = "cloudotp_admin";
const COLORS = new Set(["green", "blue", "orange", "purple", "gray"]);

function esc(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cookieValue(request, name) {
  const match = request.headers.get("Cookie")?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

function randomToken(bytes = 18) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function createLoginToken(env) {
  return encryptText(`${Date.now()}:${randomToken()}`, env.SESSION_SECRET);
}

async function verifyLoginToken(token, env, now = Date.now()) {
  try {
    const value = await decryptText(String(token || ""), env.SESSION_SECRET);
    const separator = value.indexOf(":");
    const issuedAt = Number(value.slice(0, separator));
    const nonce = value.slice(separator + 1);
    return separator > 0 && Number.isFinite(issuedAt) && nonce.length >= 16 && issuedAt <= now + 60_000 && now - issuedAt <= 600_000;
  } catch {
    return false;
  }
}

function response(body, status = 200, headers = {}) {
  const result = new Response(body, { status, headers });
  result.headers.set("Content-Type", "text/html; charset=utf-8");
  result.headers.set("Cache-Control", "no-store, private");
  result.headers.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
  result.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  result.headers.set("Referrer-Policy", "same-origin");
  result.headers.set("X-Content-Type-Options", "nosniff");
  result.headers.set("X-Frame-Options", "DENY");
  return result;
}

function redirect(location, headers = {}) {
  return response("", 303, { Location: location, ...headers });
}

function json(value, status = 200) {
  const result = response(JSON.stringify(value), status);
  result.headers.set("Content-Type", "application/json; charset=utf-8");
  return result;
}

function flashRedirect(location, message, kind = "success") {
  return redirect(`${location}${location.includes("?") ? "&" : "?"}${new URLSearchParams({ message, kind })}`);
}

function validateEnv(env) {
  for (const name of ["ADMIN_PASSWORD", "SESSION_SECRET", "APP_ENCRYPTION_KEY"]) {
    if (!env[name] || String(env[name]).startsWith("replace-with-")) throw new Error(`请先配置 ${name}`);
  }
  if (env.ADMIN_PASSWORD.length < 12) throw new Error("ADMIN_PASSWORD 至少需要 12 个字符");
}

async function sessionFor(request, env) {
  return verifySession(cookieValue(request, COOKIE), env.SESSION_SECRET);
}

async function requireAdmin(request, env) {
  const session = await sessionFor(request, env);
  return session || null;
}

async function formData(request, session) {
  const form = await request.formData();
  if (!session || !form.get("csrf") || form.get("csrf") !== session.csrf) throw new Error("页面已过期，请刷新后重试");
  return form;
}

function statusFor(row) {
  if (!row.enabled) return ["已停用", "off"];
  if (!row.expires_at) return ["长期", "neutral"];
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const days = Math.floor((new Date(`${row.expires_at}T00:00:00Z`) - today) / 86_400_000);
  if (days < 0) return ["已过期", "expired"];
  if (days <= 7) return [`${days}天到期`, "warning"];
  return ["正常", "on"];
}

const CSS = `
:root{color-scheme:light dark;--bg:#f5f7fa;--panel:#fff;--panel2:#fbfcfd;--text:#111827;--muted:#6b7280;--line:#dfe5ee;--line2:#cfd8e3;--brand:#166534;--brand2:#22c55e;--danger:#b91c1c;--soft:#eef8f1;--blue:#2563eb;--amber:#b45309;--shadow:0 14px 40px #13203612}*{box-sizing:border-box}body{margin:0;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at top,#eef8f1 0,transparent 34%),var(--bg);color:var(--text)}a{color:inherit}.shell{width:min(1180px,calc(100% - 32px));margin:auto}.top{background:#10231a;color:#fff;padding:15px 0;box-shadow:0 8px 24px #0002}.top .shell,.row{display:flex;align-items:center;gap:12px;justify-content:space-between}.brand{font-size:19px;font-weight:800;text-decoration:none}.nav{display:flex;align-items:center;gap:10px}.container{padding:28px 0 56px}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:20px}.hero h1{margin:0 0 5px;font-size:30px;line-height:1.15}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}.card{background:color-mix(in srgb,var(--panel) 96%,transparent);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:var(--shadow);backdrop-filter:blur(10px)}.stat b{display:block;font-size:30px;line-height:1;margin-top:9px}.columns{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:18px;align-items:start}.member{margin-bottom:13px;transition:border-color .15s,transform .15s,box-shadow .15s}.member:hover{border-color:color-mix(in srgb,var(--brand2) 45%,var(--line));transform:translateY(-1px);box-shadow:0 20px 50px #13203618}.member-head{display:flex;gap:14px;justify-content:space-between;align-items:start}.member h3{margin:0 0 3px;font-size:21px}.meta{display:flex;flex-wrap:wrap;gap:7px 12px;color:var(--muted);font-size:13px;margin:9px 0}.totp-wrap{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:15px 0 10px}.totp{font:800 34px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:5px;margin:0}.badge{display:inline-block;padding:3px 9px;border-radius:999px;background:var(--soft);color:var(--brand);font-size:12px;font-weight:750}.badge.off,.badge.expired{background:#fee2e2;color:#991b1b}.badge.warning{background:#fef3c7;color:#92400e}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:13px}.btn,button,input,select,textarea{font:inherit}.btn,button{appearance:none;border:1px solid var(--line2);border-radius:11px;background:var(--panel);color:var(--text);min-height:38px;padding:8px 12px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;font-weight:700;box-shadow:0 1px 2px #1018280a;transition:transform .12s,box-shadow .12s,border-color .12s,background .12s}.btn:hover,button:hover{transform:translateY(-1px);box-shadow:0 8px 22px #10182814;border-color:color-mix(in srgb,var(--brand2) 34%,var(--line2))}.btn:active,button:active{transform:translateY(0);box-shadow:0 1px 2px #1018280a}.primary{background:var(--brand);border-color:var(--brand);color:white}.primary:hover{background:#15803d}.danger{color:var(--danger);border-color:#fecaca;background:#fff7f7}.ghost{background:var(--panel2)}.copy-code{background:#111827;color:#fff;border-color:#111827}.copy-code:hover{background:#0f172a}.copy-link{color:var(--brand);border-color:#86efac;background:#f0fdf4}.icon{font-size:16px;line-height:1}.pill-action{border-radius:999px;padding-inline:14px}.action-form{display:inline-flex;margin:0}label{display:block;font-weight:650;margin:12px 0 5px}input,select,textarea{width:100%;border:1px solid var(--line2);border-radius:11px;background:var(--panel);color:var(--text);padding:11px 12px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--brand2);box-shadow:0 0 0 3px #22c55e22}textarea{min-height:72px;resize:vertical}.flash{padding:12px 15px;border-radius:12px;background:#dcfce7;color:#14532d;margin-bottom:15px}.flash.error{background:#fee2e2;color:#991b1b}.empty{text-align:center;padding:40px 20px}.login{width:min(430px,calc(100% - 32px));margin:10vh auto}.login h1{margin-top:0}.share{width:min(520px,calc(100% - 32px));margin:9vh auto;text-align:center;padding:28px}.share h1{font-size:34px;margin:22px 0 8px}.share .totp{font-size:58px;letter-spacing:8px;margin:0}.share-actions{display:grid;grid-template-columns:1fr;gap:10px;margin:22px 0 0}.share-copy{height:50px;border-radius:14px;background:var(--brand);border-color:var(--brand);color:#fff;font-size:16px}.bar{height:9px;background:var(--line);border-radius:99px;overflow:hidden;margin-top:16px}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--brand2),#16a34a);transition:width .4s}.log{display:grid;grid-template-columns:1fr 1fr 1.3fr 1fr;gap:10px;border-bottom:1px solid var(--line);padding:10px 0;font-size:13px}.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.note{font-size:13px;background:var(--soft);border-radius:11px;padding:12px;margin-top:12px}.toast{position:fixed;left:50%;bottom:28px;z-index:20;transform:translate(-50%,14px);opacity:0;background:#111827;color:#fff;border-radius:999px;padding:10px 14px;font-size:13px;font-weight:750;box-shadow:0 18px 45px #11182740;pointer-events:none;transition:.18s}.toast.show{opacity:1;transform:translate(-50%,0)}@media(prefers-color-scheme:dark){:root{--bg:#0c1410;--panel:#142019;--panel2:#101a15;--text:#e9f3ec;--muted:#a0aca5;--line:#2b3a31;--line2:#3a4a40;--brand:#15803d;--soft:#193023;--shadow:0 16px 44px #0005}.danger{background:#2a1515}.copy-code{background:#e9f3ec;color:#10231a;border-color:#e9f3ec}.toast{background:#e9f3ec;color:#10231a}}@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.columns{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}.log{grid-template-columns:1fr 1fr}}@media(max-width:520px){.shell{width:min(100% - 20px,1180px)}.grid{grid-template-columns:1fr 1fr}.top .shell{align-items:flex-start}.nav{flex-wrap:wrap;justify-content:flex-end}.member-head{display:block}.totp{font-size:30px}.share{margin:7vh auto}.share .totp{font-size:44px;letter-spacing:5px}.log{grid-template-columns:1fr}.hide-mobile{display:none}}
`;

function layout(title, content, session = null) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · TOTP 看板</title><style>${CSS}</style></head><body>
  <header class="top"><div class="shell"><a class="brand" href="/">2FA 验证码共享看板</a>${session ? `<nav class="nav"><a class="btn" href="/admin">看板</a><a class="btn" href="/admin/logs">访问记录</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button>退出</button></form></nav>` : ""}</div></header>
  ${content}</body></html>`;
}

function messageBlock(url) {
  const message = url.searchParams.get("message");
  return message ? `<div class="flash ${url.searchParams.get("kind") === "error" ? "error" : ""}">${esc(message)}</div>` : "";
}

async function loginPage(url, csrf, error = "") {
  return layout("登录", `<main class="login card"><h1>管理员登录</h1><p class="muted">登录后管理会员、分享链接和实时验证码。</p>${error ? `<div class="flash error">${esc(error)}</div>` : messageBlock(url)}<form method="post"><input type="hidden" name="csrf" value="${esc(csrf)}"><label for="username">账号</label><input id="username" name="username" autocomplete="username" value="admin" required><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="primary" style="width:100%;margin-top:18px">登录</button></form></main>`);
}

async function dashboard(request, env, session, url) {
  const [{ results: vehicles }, { results: categories }, active, views] = await Promise.all([
    env.DB.prepare("SELECT * FROM vehicles ORDER BY code ASC").all(),
    env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM vehicles WHERE enabled = 1").first(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM access_logs WHERE date(created_at) = date('now')").first(),
  ]);
  let expiring = 0;
  const cards = [];
  for (const vehicle of vehicles) {
    const [label, kind] = statusFor(vehicle);
    if (kind === "warning") expiring += 1;
    let token = "";
    try { token = await decryptText(vehicle.share_token_cipher, env.APP_ENCRYPTION_KEY); } catch { token = "无法解密"; }
    const shareUrl = `${url.origin}/s/${token}`;
    cards.push(`<article class="card member" data-member data-name="${esc(`${vehicle.name} ${vehicle.code} ${vehicle.account}`.toLowerCase())}" data-category="${esc(vehicle.category)}"><div class="member-head"><div><h3>${esc(vehicle.name)}</h3><span class="muted">${esc(vehicle.code)}</span></div><span class="badge ${kind}">${label}</span></div><div class="meta"><span>${esc(vehicle.category)}</span>${vehicle.account ? `<span>${esc(vehicle.account)}</span>` : ""}${vehicle.expires_at ? `<span>到期 ${esc(vehicle.expires_at)}</span>` : ""}</div><div class="totp-wrap"><div class="totp" data-code-id="${vehicle.id}" data-plain-code="">••• •••</div><button type="button" class="copy-code pill-action" data-copy-code-button><span class="icon">⧉</span>复制验证码</button></div><div class="muted" data-remaining-id="${vehicle.id}">正在获取验证码</div>${vehicle.notes ? `<p class="note">${esc(vehicle.notes)}</p>` : ""}<label>分享链接</label><input class="code" value="${esc(shareUrl)}" readonly data-copy><div class="actions"><button type="button" class="copy-link pill-action" data-copy-button><span class="icon">↗</span>复制链接</button><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/toggle"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="ghost pill-action"><span class="icon">${vehicle.enabled ? "⏸" : "▶"}</span>${vehicle.enabled ? "停用分享" : "启用分享"}</button></form><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/rotate" onsubmit="return confirm('旧链接将立即失效，确定重置？')"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="ghost pill-action"><span class="icon">↻</span>重置链接</button></form><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/delete" onsubmit="return confirm('确定删除此会员及访问记录？')"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="danger pill-action"><span class="icon">×</span>删除</button></form></div></article>`);
  }
  const options = categories.map((category) => `<option value="${esc(category.name)}">${esc(category.name)}</option>`).join("");
  const content = `<main class="shell container">${messageBlock(url)}<section class="hero"><div><h1>会员与验证码</h1><div class="muted">Cloudflare Workers + D1 · 密钥加密保存</div></div><input id="search" style="max-width:320px" placeholder="搜索名称、编号或账号"></section><section class="grid"><div class="card stat"><span class="muted">会员总数</span><b>${vehicles.length}</b></div><div class="card stat"><span class="muted">已启用</span><b>${active?.count || 0}</b></div><div class="card stat"><span class="muted">7 天内到期</span><b>${expiring}</b></div><div class="card stat"><span class="muted">今日访问</span><b>${views?.count || 0}</b></div></section><div class="columns"><section><div class="row" style="margin-bottom:12px"><select id="category-filter" style="max-width:190px"><option value="">全部分类</option>${options}</select><span class="muted"><span id="visible-count">${vehicles.length}</span> 项</span></div><div id="members">${cards.join("") || `<div class="card empty"><h3>还没有会员</h3><p class="muted">用右侧表单添加第一个 TOTP 账号。</p></div>`}</div></section><aside class="card"><h2 style="margin-top:0">添加会员</h2><form method="post" action="/admin/vehicles"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>名称</label><input name="name" required maxlength="80" placeholder="例如 ChatGPT 团队账号"><label>编号</label><input name="code" required maxlength="20" placeholder="例如 001"><label>账号</label><input name="account" maxlength="160" placeholder="member@example.com"><label>分类</label><select name="category">${options}</select><label>到期日期</label><input name="expires_at" type="date"><label>Base32 密钥</label><input name="secret" required autocomplete="off" placeholder="JBSWY3DPEHPK3PXP"><label>备注</label><textarea name="notes" maxlength="2000"></textarea><button class="primary" style="width:100%;margin-top:16px">保存并生成分享链接</button></form><hr style="border:0;border-top:1px solid var(--line);margin:22px 0"><h3>添加分类</h3><form method="post" action="/admin/categories"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>分类名称</label><input name="name" required maxlength="80"><label>颜色</label><select name="color"><option value="green">绿色</option><option value="blue">蓝色</option><option value="orange">橙色</option><option value="purple">紫色</option><option value="gray">灰色</option></select><button style="width:100%;margin-top:12px">添加分类</button></form></aside></div></main>`;
  return layout("管理看板", content, session).replace("</body>", `<script>
const search=document.querySelector('#search'),filter=document.querySelector('#category-filter'),members=[...document.querySelectorAll('[data-member]')],count=document.querySelector('#visible-count');function apply(){const q=search.value.trim().toLowerCase(),c=filter.value;let n=0;for(const el of members){const show=(!q||el.dataset.name.includes(q))&&(!c||el.dataset.category===c);el.hidden=!show;if(show)n++}count.textContent=n}search.addEventListener('input',apply);filter.addEventListener('change',apply);
function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}
async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}
document.addEventListener('click',async e=>{const linkBtn=e.target.closest('[data-copy-button]'),codeBtn=e.target.closest('[data-copy-code-button]');if(!linkBtn&&!codeBtn)return;const member=e.target.closest('.member');if(linkBtn){const input=member.querySelector('[data-copy]');await copyText(input.value);linkBtn.innerHTML='<span class="icon">✓</span>已复制';toast('分享链接已复制');setTimeout(()=>linkBtn.innerHTML='<span class="icon">↗</span>复制链接',1200)}if(codeBtn){const code=member.querySelector('[data-code-id]').dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);codeBtn.innerHTML='<span class="icon">✓</span>已复制';toast('验证码已复制');setTimeout(()=>codeBtn.innerHTML='<span class="icon">⧉</span>复制验证码',1200)}});
async function codes(){try{const r=await fetch('/api/admin/codes',{cache:'no-store'});if(!r.ok)return;for(const item of await r.json()){const code=document.querySelector('[data-code-id="'+item.id+'"]'),left=document.querySelector('[data-remaining-id="'+item.id+'"]');if(code){code.textContent=item.code.slice(0,3)+' '+item.code.slice(3);code.dataset.plainCode=item.code}if(left)left.textContent=item.remaining+' 秒后更新'}}catch{}}codes();setInterval(codes,1000);
</script></body>`);
}

async function sharePage(env, vehicle, token) {
  return layout("查看验证码", `<main class="share card"><span class="badge">${esc(vehicle.category)}</span><h1>${esc(vehicle.name)}</h1><p class="muted">编号 ${esc(vehicle.code)}${vehicle.account ? ` · ${esc(vehicle.account)}` : ""}</p><div class="totp" id="code" data-plain-code="">••• •••</div><p class="muted"><span id="remaining">--</span> 秒后更新</p><div class="bar"><i id="bar" style="width:100%"></i></div><div class="share-actions"><button type="button" class="share-copy" id="copy-code"><span class="icon">⧉</span>复制验证码</button></div><p class="note">验证码属于敏感凭据，请勿截图或转发本页面。</p></main><script>function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}document.querySelector('#copy-code').addEventListener('click',async()=>{const code=document.querySelector('#code').dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);document.querySelector('#copy-code').innerHTML='<span class="icon">✓</span>已复制';toast('验证码已复制');setTimeout(()=>document.querySelector('#copy-code').innerHTML='<span class="icon">⧉</span>复制验证码',1200)});async function update(){try{const r=await fetch('/api/s/${esc(token)}/code',{cache:'no-store'});if(!r.ok)throw 0;const d=await r.json();document.querySelector('#code').textContent=d.code.slice(0,3)+' '+d.code.slice(3);document.querySelector('#code').dataset.plainCode=d.code;document.querySelector('#remaining').textContent=d.remaining;document.querySelector('#bar').style.width=(d.remaining/30*100)+'%'}catch{document.querySelector('#code').textContent='链接已失效';document.querySelector('#copy-code').disabled=true}}update();setInterval(update,1000)</script>`);
}

async function findShared(env, token) {
  if (token.length < 12) return null;
  return env.DB.prepare("SELECT * FROM vehicles WHERE share_token_hash = ? AND enabled = 1").bind(await sha256(token)).first();
}

async function handle(request, env) {
  validateEnv(env);
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const secureCookie = url.protocol === "https:" ? "; Secure" : "";
  if (path === "/health") return json({ status: "ok", runtime: "cloudflare-workers", database: "d1" });

  if (path === "/login") {
    if (method === "GET") {
      if (await sessionFor(request, env)) return redirect("/admin");
      return response(await loginPage(url, await createLoginToken(env)));
    }
    if (method === "POST") {
      const form = await request.formData();
      if (!await verifyLoginToken(form.get("csrf"), env)) return response(await loginPage(url, await createLoginToken(env), "页面已过期，请刷新后重试"), 403);
      if (!constantTimeEqual(form.get("username"), "admin") || !constantTimeEqual(form.get("password"), env.ADMIN_PASSWORD)) return response(await loginPage(url, await createLoginToken(env), "账号或密码不正确"), 401);
      const csrf = randomToken();
      const signed = await createSession(env.SESSION_SECRET, csrf);
      return redirect("/admin", { "Set-Cookie": `${COOKIE}=${encodeURIComponent(signed)}; Path=/; HttpOnly${secureCookie}; SameSite=Lax; Max-Age=43200` });
    }
  }

  if (path === "/") return redirect((await sessionFor(request, env)) ? "/admin" : "/login");

  const shareMatch = path.match(/^\/s\/([A-Za-z0-9_-]+)$/);
  if (shareMatch && method === "GET") {
    const vehicle = await findShared(env, shareMatch[1]);
    if (!vehicle) return response(layout("链接无效", `<main class="share card"><h1>分享链接无效</h1><p class="muted">链接可能已被停用或重置。</p></main>`), 404);
    await env.DB.prepare("INSERT INTO access_logs(vehicle_id, ip_address, user_agent) VALUES (?, ?, ?)").bind(vehicle.id, (request.headers.get("CF-Connecting-IP") || "unknown").slice(0, 64), (request.headers.get("User-Agent") || "unknown").slice(0, 255)).run();
    return response(await sharePage(env, vehicle, shareMatch[1]));
  }

  const shareApi = path.match(/^\/api\/s\/([A-Za-z0-9_-]+)\/code$/);
  if (shareApi && method === "GET") {
    const vehicle = await findShared(env, shareApi[1]);
    if (!vehicle) return json({ error: "not_found" }, 404);
    const secret = await decryptText(vehicle.secret_cipher, env.APP_ENCRYPTION_KEY);
    return json({ code: await totp(secret), remaining: 30 - (Math.floor(Date.now() / 1000) % 30), name: vehicle.name, vehicle_code: vehicle.code });
  }

  const session = await requireAdmin(request, env);
  if (!session) return redirect("/login");

  if (path === "/admin" && method === "GET") return response(await dashboard(request, env, session, url));

  if (path === "/logout" && method === "POST") {
    await formData(request, session);
    return redirect("/login", { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly${secureCookie}; SameSite=Lax; Max-Age=0` });
  }

  if (path === "/admin/vehicles" && method === "POST") {
    try {
      const form = await formData(request, session);
      const name = String(form.get("name") || "").trim();
      const code = String(form.get("code") || "").trim();
      const category = String(form.get("category") || "未分类").trim() || "未分类";
      if (!name || !code) throw new Error("名称和编号不能为空");
      if (!await env.DB.prepare("SELECT id FROM categories WHERE name = ?").bind(category).first()) throw new Error("请选择有效分类");
      const secret = normalizeSecret(String(form.get("secret") || ""));
      const token = randomToken(9);
      await env.DB.prepare("INSERT INTO vehicles(name, code, category, account, expires_at, notes, secret_cipher, share_token_cipher, share_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(name, code, category, String(form.get("account") || "").trim(), form.get("expires_at") || null, String(form.get("notes") || "").trim(), await encryptText(secret, env.APP_ENCRYPTION_KEY), await encryptText(token, env.APP_ENCRYPTION_KEY), await sha256(token)).run();
      return flashRedirect("/admin", "会员已添加，专属链接已生成");
    } catch (error) {
      return flashRedirect("/admin", `保存失败：${error.message.includes("UNIQUE") ? "编号已经存在" : error.message}`, "error");
    }
  }

  if (path === "/admin/categories" && method === "POST") {
    try {
      const form = await formData(request, session);
      const name = String(form.get("name") || "").trim();
      const color = COLORS.has(form.get("color")) ? form.get("color") : "green";
      if (!name) throw new Error("分类名称不能为空");
      await env.DB.prepare("INSERT INTO categories(name, color) VALUES (?, ?)").bind(name, color).run();
      return flashRedirect("/admin", "分类已添加");
    } catch (error) {
      return flashRedirect("/admin", `保存失败：${error.message.includes("UNIQUE") ? "分类已经存在" : error.message}`, "error");
    }
  }

  const vehicleAction = path.match(/^\/admin\/vehicles\/(\d+)\/(toggle|rotate|delete)$/);
  if (vehicleAction && method === "POST") {
    await formData(request, session);
    const id = Number(vehicleAction[1]);
    const action = vehicleAction[2];
    if (action === "toggle") await env.DB.prepare("UPDATE vehicles SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id = ?").bind(id).run();
    if (action === "rotate") {
      const token = randomToken(9);
      await env.DB.prepare("UPDATE vehicles SET share_token_cipher = ?, share_token_hash = ?, enabled = 1 WHERE id = ?").bind(await encryptText(token, env.APP_ENCRYPTION_KEY), await sha256(token), id).run();
    }
    if (action === "delete") await env.DB.batch([env.DB.prepare("DELETE FROM access_logs WHERE vehicle_id = ?").bind(id), env.DB.prepare("DELETE FROM vehicles WHERE id = ?").bind(id)]);
    return flashRedirect("/admin", action === "rotate" ? "已生成新链接，旧链接立即失效" : action === "delete" ? "会员已删除" : "分享状态已更新");
  }

  if (path === "/api/admin/codes" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, secret_cipher, enabled FROM vehicles ORDER BY code ASC").all();
    const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    return json(await Promise.all(results.map(async (row) => ({ id: row.id, enabled: Boolean(row.enabled), code: await totp(await decryptText(row.secret_cipher, env.APP_ENCRYPTION_KEY)), remaining }))));
  }

  if (path === "/admin/logs" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT access_logs.*, vehicles.name, vehicles.code FROM access_logs JOIN vehicles ON vehicles.id = access_logs.vehicle_id ORDER BY access_logs.created_at DESC LIMIT 300").all();
    const rows = results.map((row) => `<div class="log"><strong>${esc(row.name)} <span class="muted">${esc(row.code)}</span></strong><span class="code">${esc(row.ip_address)}</span><span class="hide-mobile">${esc(row.user_agent)}</span><span>${esc(row.created_at)} UTC</span></div>`).join("");
    return response(layout("访问记录", `<main class="shell container"><section class="hero"><div><h1>最近访问记录</h1><div class="muted">最多显示 300 条</div></div></section><div class="card">${rows || `<div class="empty">暂无访问记录</div>`}</div></main>`, session));
  }

  return response(layout("未找到", `<main class="share card"><h1>404</h1><p class="muted">页面不存在。</p></main>`, session), 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      console.error(error);
      return response(layout("配置错误", `<main class="share card"><h1>服务暂不可用</h1><p class="muted">${esc(error.message)}</p><p class="note">请在 Cloudflare Worker 设置中检查 D1 绑定和三个 Secret。</p></main>`), 500);
    }
  },
};
