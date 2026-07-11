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

const CSS = `
:root{color-scheme:light;--background:#f8fafc;--foreground:#0f172a;--card:#fff;--card-foreground:#0f172a;--muted:#f1f5f9;--muted-foreground:#64748b;--border:#e2e8f0;--input:#cbd5e1;--primary:#0f172a;--primary-foreground:#fff;--secondary:#f8fafc;--secondary-foreground:#0f172a;--accent:#f1f5f9;--accent-foreground:#0f172a;--destructive:#dc2626;--destructive-foreground:#fff;--ring:#94a3b8;--success:#16a34a;--success-bg:#dcfce7;--warning:#d97706;--warning-bg:#fef3c7;--radius:12px;--shadow:0 1px 2px rgba(15,23,42,.05)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--background);color:var(--foreground);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;letter-spacing:0}a{color:inherit;text-decoration:none}.top{border-bottom:1px solid var(--border);background:rgba(255,255,255,.85);backdrop-filter:blur(12px);padding:14px 0}.shell{width:min(1180px,calc(100% - 32px));margin:auto}.top .shell,.row,.topbar,.actions,.member-title,.inline{display:flex;align-items:center}.top .shell,.topbar{justify-content:space-between;gap:16px}.brand{font-size:18px;font-weight:800}.nav{display:flex;gap:8px}.app-shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;border-right:1px solid var(--border);background:#fff;padding:18px 14px;display:flex;flex-direction:column;gap:18px}.sidebar-brand{display:flex;align-items:center;gap:10px;padding:6px 8px}.mark{width:36px;height:36px;border-radius:10px;background:var(--primary);color:#fff;display:grid;place-items:center;font-weight:900}.sidebar-brand strong{display:block}.sidebar-brand span,.sub,.muted{color:var(--muted-foreground)}.sidebar-brand span{font-size:12px}.side-nav{display:grid;gap:5px}.side-nav a,.side-nav button{justify-content:flex-start;width:100%;border:0;box-shadow:none;background:transparent;color:var(--muted-foreground);font-weight:700}.side-nav .active{background:var(--accent);color:var(--accent-foreground)}.side-footer{margin-top:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--secondary);padding:12px;color:var(--muted-foreground);font-size:12px}.main{min-width:0;padding:24px}.topbar{margin-bottom:18px}.title h1{margin:0;font-size:28px;line-height:1.2}.title p{margin:5px 0 0;color:var(--muted-foreground)}.layout-grid{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:16px;align-items:start}.kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}.card-pad{padding:16px}.kpi{padding:16px}.kpi span{color:var(--muted-foreground);font-size:13px}.kpi b{display:block;margin-top:8px;font-size:28px;line-height:1}.toolbar{display:grid;grid-template-columns:minmax(260px,1fr) 170px 96px;gap:10px;padding:12px;margin-bottom:12px}.table-card{overflow:hidden}.table-head{padding:15px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px}.table-head h2{margin:0;font-size:16px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:880px}th,td{padding:12px 14px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}th{height:40px;background:#fbfdff;color:var(--muted-foreground);font-size:12px;font-weight:800}tr:hover{background:#fafafa}.member-title{gap:10px}.avatar{width:34px;height:34px;border-radius:10px;background:var(--muted);display:grid;place-items:center;font-weight:900;color:#334155}.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.totp{font:800 20px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:1.5px;white-space:nowrap}.badge{display:inline-flex;align-items:center;gap:5px;height:24px;padding:0 8px;border-radius:999px;font-size:12px;font-weight:800;background:var(--secondary);color:var(--secondary-foreground)}.badge.neutral,.badge.on{background:var(--success-bg);color:#166534}.badge.warning{background:var(--warning-bg);color:#92400e}.badge.off,.badge.expired,.badge.destructive{background:#fee2e2;color:#991b1b}.btn,button,input,select,textarea{font:inherit}.btn,button{appearance:none;border:1px solid var(--border);border-radius:10px;background:#fff;color:var(--foreground);min-height:36px;padding:8px 12px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px;font-weight:750;box-shadow:var(--shadow);transition:background .12s,border-color .12s,transform .12s}.btn:hover,button:hover{background:var(--accent);border-color:var(--input)}.btn:active,button:active{transform:translateY(1px)}.primary{background:var(--primary);border-color:var(--primary);color:var(--primary-foreground)}.primary:hover{background:#1e293b}.danger{color:var(--destructive);border-color:#fecaca}.copy-code{background:var(--primary);border-color:var(--primary);color:#fff}.copy-code:hover{background:#1e293b}.copy-link{color:#166534;border-color:#bbf7d0;background:#f0fdf4}.copy-link:hover{background:#dcfce7}.ghost{background:#fff}.icon-btn{width:36px;padding:0}.pill-action{border-radius:999px}.action-form{display:inline-flex;margin:0}.row-actions{display:flex;gap:6px;flex-wrap:wrap}.icon{font-size:15px;line-height:1}.form-card{padding:16px}.form-card h2,.form-card h3{margin:0 0 10px;font-size:16px}label{display:block;margin:11px 0 5px;font-weight:750}input,select,textarea{width:100%;border:1px solid var(--input);border-radius:10px;background:#fff;color:var(--foreground);padding:10px 11px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--ring);box-shadow:0 0 0 3px rgba(148,163,184,.22)}textarea{min-height:74px;resize:vertical}.flash{padding:12px 14px;border-radius:var(--radius);background:var(--success-bg);color:#166534;margin-bottom:12px;font-weight:700}.flash.error{background:#fee2e2;color:#991b1b}.empty{text-align:center;padding:42px 16px;color:var(--muted-foreground)}.login{width:min(430px,calc(100% - 32px));margin:10vh auto;padding:24px}.login h1{margin:0 0 6px}.share-shell{min-height:calc(100vh - 65px);display:grid;place-items:center;padding:32px 16px;background:radial-gradient(circle at top,#dcfce7 0,transparent 36%),var(--background)}.share{width:min(500px,100%);text-align:center;padding:28px}.share h1{font-size:34px;margin:20px 0 6px}.share .totp{font-size:56px;letter-spacing:7px;margin:22px 0 8px}.bar{height:9px;background:var(--border);border-radius:999px;overflow:hidden;margin:18px 0}.bar i{display:block;height:100%;background:var(--success);transition:width .4s}.share-copy{width:100%;height:48px;background:var(--primary);border-color:var(--primary);color:#fff;border-radius:12px;font-size:16px}.note{font-size:13px;background:var(--secondary);border-radius:var(--radius);padding:11px;margin-top:12px;color:var(--muted-foreground)}.logs-table td{font-size:13px}.toast{position:fixed;left:50%;bottom:28px;z-index:20;transform:translate(-50%,14px);opacity:0;background:var(--primary);color:#fff;border-radius:999px;padding:10px 14px;font-size:13px;font-weight:800;box-shadow:0 18px 45px rgba(15,23,42,.28);pointer-events:none;transition:.18s}.toast.show{opacity:1;transform:translate(-50%,0)}[hidden]{display:none!important}@media(prefers-color-scheme:dark){:root{color-scheme:dark;--background:#020617;--foreground:#e2e8f0;--card:#0f172a;--card-foreground:#e2e8f0;--muted:#1e293b;--muted-foreground:#94a3b8;--border:#1e293b;--input:#334155;--primary:#e2e8f0;--primary-foreground:#020617;--secondary:#111827;--secondary-foreground:#e2e8f0;--accent:#1e293b;--accent-foreground:#f8fafc;--ring:#475569;--shadow:none}.top,.sidebar,.card,input,select,textarea,.btn,button{background:var(--card)}th{background:#111827}tr:hover{background:#111827}.copy-code,.share-copy,.primary,.toast{background:var(--primary);color:var(--primary-foreground);border-color:var(--primary)}.copy-code:hover,.share-copy:hover,.primary:hover{background:#cbd5e1}.copy-link{background:#052e16}.danger{background:#2a1214}.mark{background:var(--primary);color:var(--primary-foreground)}}@media(max-width:1050px){.app-shell{grid-template-columns:1fr}.sidebar{position:static;height:auto}.side-nav{grid-template-columns:repeat(4,1fr)}.side-footer{display:none}.layout-grid{grid-template-columns:1fr}.kpi-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:640px){.main{padding:16px}.topbar{align-items:flex-start;flex-direction:column}.toolbar{grid-template-columns:1fr}.kpi-grid{grid-template-columns:1fr 1fr}.side-nav{grid-template-columns:1fr 1fr}.share .totp{font-size:42px;letter-spacing:4px}table{min-width:760px}}
.login-page{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 0,#e0f2fe 0,transparent 34%),var(--background)}.login{margin:0;padding:24px;border-radius:18px}.login-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:14px}.login-logo{display:flex;align-items:center;gap:12px;font-size:24px;font-weight:900}.theme-toggle{width:42px;height:42px;border-radius:14px;padding:0;background:var(--card)}.theme-toggle .moon{display:none}body.dark .theme-toggle .sun{display:none}body.dark .theme-toggle .moon{display:inline}body.dark{color-scheme:dark;--background:#070b16;--foreground:#e8eef8;--card:#101827;--card-foreground:#e8eef8;--muted:#182235;--muted-foreground:#9aa8bd;--border:#263244;--input:#3a4658;--primary:#e8eef8;--primary-foreground:#070b16;--secondary:#151f31;--secondary-foreground:#e8eef8;--accent:#1f2a3d;--accent-foreground:#f8fafc;--ring:#64748b;--shadow:0 18px 50px rgba(0,0,0,.22)}body.dark,body.dark .app-shell,body.dark .main{background:var(--background);color:var(--foreground)}body.dark .top,body.dark .sidebar,body.dark .card,body.dark input,body.dark select,body.dark textarea,body.dark .btn,body.dark button{background:var(--card);color:var(--foreground);border-color:var(--border)}body.dark .sidebar{background:#0b1220}body.dark .side-footer,body.dark .toolbar,body.dark .note{background:var(--secondary)}body.dark th{background:#151f31}body.dark tr:hover{background:#121c2d}body.dark input::placeholder,body.dark textarea::placeholder{color:#6f7f95}body.dark .primary,body.dark .toast{background:#e8eef8;color:#070b16;border-color:#e8eef8}body.dark .primary:hover{background:#cbd5e1}body.dark .copy-link{background:#101827;color:#e8eef8;border-color:#334155}body.dark .reset-link,body.dark .danger{background:#3b161a;color:#fecaca;border-color:#7f1d1d}body.dark .sidebar-brand .mark,body.dark .mark{background:#e8eef8;color:#070b16}.otp-copy{border:0;background:transparent;box-shadow:none;padding:0;color:var(--foreground);font:800 22px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:2px}.otp-copy:hover{background:transparent;transform:none}.share-otp{display:block;width:100%;margin:22px 0 8px;padding:24px 12px;border:1px solid var(--border);border-radius:18px;background:var(--secondary);font-size:56px;letter-spacing:7px}.share-theme{position:absolute;right:24px;top:24px}.link-actions{gap:12px}.reset-link{background:#fee2e2;color:#991b1b;border-color:#fecaca}.reset-link:hover{background:#fecaca}.copy-link{color:var(--foreground);border-color:var(--border);background:var(--card)}.toolbar{grid-template-columns:minmax(260px,1fr) auto}.form-row{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(280px,.8fr);gap:16px;margin-bottom:16px}.form-split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.edit-card{max-width:920px}.tag-row,.setting-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border)}.tag-row:last-child,.setting-row:last-child{border-bottom:0}.tag-dot{width:11px;height:11px;border-radius:99px;background:#22c55e;box-shadow:0 0 0 4px #dcfce7}.tag-dot.blue{background:#3b82f6;box-shadow:0 0 0 4px #dbeafe}.tag-dot.orange{background:#f97316;box-shadow:0 0 0 4px #fed7aa}.tag-dot.purple{background:#8b5cf6;box-shadow:0 0 0 4px #ede9fe}.tag-dot.gray{background:#64748b;box-shadow:0 0 0 4px #e2e8f0}body.dark .tag-dot{box-shadow:0 0 0 4px rgba(34,197,94,.14)}body.dark .tag-dot.blue{box-shadow:0 0 0 4px rgba(59,130,246,.16)}body.dark .tag-dot.orange{box-shadow:0 0 0 4px rgba(249,115,22,.16)}body.dark .tag-dot.purple{box-shadow:0 0 0 4px rgba(139,92,246,.16)}body.dark .tag-dot.gray{box-shadow:0 0 0 4px rgba(100,116,139,.2)}@media(max-width:640px){body{background:#111}.top{display:none}.app-shell{display:block;min-height:100vh;background:var(--background)}.sidebar{display:none}.main{width:430px;max-width:100%;min-height:900px;margin:0 auto;padding:0 16px 24px;border-left:1px solid var(--border);border-right:1px solid var(--border);background:var(--background)}.topbar{height:82px;margin:0 -16px 16px;padding:16px 20px;display:grid;grid-template-columns:42px 1fr 42px;align-items:center;border-bottom:1px solid var(--border);background:rgba(255,255,255,.9);backdrop-filter:blur(10px)}.topbar:before{content:'☰';grid-column:1;font-size:26px;font-weight:900}body.dark .topbar{background:rgba(11,18,32,.92)}.title{grid-column:2;text-align:center}.title h1{font-size:0}.title h1:after{content:'CloudOTP';font-size:22px}.title p{display:none}.actions{grid-column:3;justify-content:end}.actions .primary{position:fixed;right:20px;bottom:24px;width:58px;height:58px;border-radius:19px;font-size:0;z-index:5}.actions .primary .icon{font-size:28px}.theme-toggle{width:36px;height:36px}.kpi-grid{display:none}.layout-grid{display:block}.toolbar{grid-template-columns:1fr;margin-bottom:12px;padding:0;border:0;background:transparent;box-shadow:none}.toolbar input{height:54px;font-size:16px}.toolbar select,.toolbar .badge{display:none}.table-head{display:none}.table-card{border:0;background:transparent;box-shadow:none}.table-wrap{overflow:visible}table,tbody{display:block;min-width:0;width:100%}thead{display:none}tr.member{display:grid;grid-template-columns:52px minmax(0,1fr) max-content;gap:12px;margin:0 0 12px;padding:14px 16px;border:1px solid var(--border);border-radius:18px;background:var(--card);box-shadow:var(--shadow)}tr.member:hover{background:var(--card)}tr.member td{display:block;border:0;padding:0}tr.member td:before{content:none}tr.member td[data-label='账号']{grid-column:1/3}tr.member td[data-label='账号'] .member-title{display:grid;grid-template-columns:52px minmax(0,1fr);gap:12px}tr.member td[data-label='账号'] .avatar{width:52px;height:52px;border-radius:15px;font-size:22px}tr.member td[data-label='标签'],tr.member td[data-label='操作']{display:none}tr.member td[data-label='验证码']{grid-column:3;grid-row:1;text-align:right;align-self:center}.otp-copy{font-size:27px;letter-spacing:1.5px}tr.member td[data-label='验证码'] .sub{display:none}tr.member td[data-label='分享链接']{grid-column:2/4}.link-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.link-actions button{width:100%;min-height:40px}.form-card{margin-top:16px}.form-row{grid-template-columns:1fr}.form-split{grid-template-columns:1fr 1fr}.login-page{display:block;background:#111;padding:0}.login-page .login{position:absolute;left:16px;right:16px;top:50%;transform:translateY(-50%);width:auto}.login-logo{font-size:24px}.share-shell{min-height:100vh}.share .totp,.share-otp{font-size:42px;letter-spacing:4px}}
.main{max-width:1480px;width:100%;margin:0 auto}.form-row{align-items:start}.compact-card{align-self:start}.account-form{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.account-form .wide{grid-column:1/-1}.account-form button{justify-self:start;margin-top:14px}.form-card textarea{min-height:64px}.table-card{margin-top:0}.table-wrap table{min-width:760px}.edit-btn{min-width:72px}@media(max-width:900px){.form-row{grid-template-columns:1fr}.account-form{grid-template-columns:1fr}}@media(max-width:640px){.main{max-width:430px}.topbar{grid-template-columns:1fr 42px}.topbar:before{content:none}.title{grid-column:1;text-align:left}.actions{grid-column:2}.actions .primary{display:none}.account-form{display:block}tr.member{grid-template-columns:52px minmax(0,1fr);gap:12px}tr.member td[data-label='操作']{display:block;grid-column:1/3;grid-row:auto}.edit-btn{width:100%;min-height:40px}.icon-btn{width:38px;height:38px}tr.member td[data-label='分享链接']{grid-column:1/3}.link-actions{grid-template-columns:1fr 1fr}.form-row{margin-bottom:14px}.form-card textarea{min-height:80px}}
`;

const LIGHT_CSS = `body.light{color-scheme:light;--background:#f8fafc;--foreground:#0f172a;--card:#fff;--card-foreground:#0f172a;--muted:#f1f5f9;--muted-foreground:#64748b;--border:#e2e8f0;--input:#cbd5e1;--primary:#0f172a;--primary-foreground:#fff;--secondary:#f8fafc;--secondary-foreground:#0f172a;--accent:#f1f5f9;--accent-foreground:#0f172a;--ring:#94a3b8;--shadow:0 1px 2px rgba(15,23,42,.05)}body.light,body.light .app-shell,body.light .main{background:var(--background);color:var(--foreground)}body.light .top,body.light .sidebar,body.light .card,body.light input,body.light select,body.light textarea,body.light .btn,body.light button{background:var(--card);color:var(--foreground);border-color:var(--border)}body.light th{background:#fbfdff}body.light tr:hover{background:#fafafa}`;

function layout(title, content, session = null) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · TOTP 看板</title><style>${CSS}${LIGHT_CSS}</style></head><body>
  ${session ? "" : `<header class="top"><div class="shell"><a class="brand" href="/">CloudOTP</a></div></header>`}
  ${content}<script>
const themeModes=['system','light','dark'];
function applyTheme(mode){document.body.classList.toggle('light',mode==='light');document.body.classList.toggle('dark',mode==='dark');document.querySelectorAll('[data-theme-toggle]').forEach(btn=>{btn.textContent=mode==='system'?'◐':mode==='light'?'☀':'☾';btn.title=mode==='system'?'主题：跟随系统':mode==='light'?'主题：日间模式':'主题：夜间模式';btn.setAttribute('aria-label',btn.title)})}
function toggleTheme(){let mode='system';try{mode=localStorage.getItem('cloudotp-theme')||'system'}catch{}const next=themeModes[(themeModes.indexOf(mode)+1)%themeModes.length];try{localStorage.setItem('cloudotp-theme',next)}catch{}applyTheme(next)}
let savedTheme='system';try{savedTheme=localStorage.getItem('cloudotp-theme')||'system'}catch{}applyTheme(themeModes.includes(savedTheme)?savedTheme:'system');
document.addEventListener('click',e=>{const btn=e.target.closest('[data-theme-toggle]');if(btn)toggleTheme()});
</script></body></html>`;
}

function messageBlock(url) {
  const message = url.searchParams.get("message");
  return message ? `<div class="flash ${url.searchParams.get("kind") === "error" ? "error" : ""}">${esc(message)}</div>` : "";
}

function adminShell(active, title, subtitle, body, session) {
  const nav = [
    ["首页", "/admin", "▦"],
    ["添加账号", "/admin#add-account", "♁"],
    ["添加标签", "/admin#add-label", "◇"],
  ];
  const primary = `<a class="btn primary" href="/admin#add-account"><span class="icon">+</span>添加账号</a>`;
  return `<div class="app-shell"><aside class="sidebar"><a class="sidebar-brand" href="/admin"><span class="mark">☁</span><span><strong>CloudOTP</strong><span>2FA 分享控制台</span></span></a><nav class="side-nav">${nav.map(([name, href, icon], index) => `<a class="btn ${index === 0 && active === "/admin" ? "active" : ""}" href="${href}"><span class="icon">${icon}</span>${name}</a>`).join("")}<form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button><span class="icon">⏻</span>退出登录</button></form></nav></aside><main class="main"><section class="topbar"><div class="title"><h1>${esc(title)}</h1><p>${esc(subtitle)}</p></div><div class="actions"><button class="theme-toggle" type="button" data-theme-toggle aria-label="切换日间夜间"><span class="sun">☀</span><span class="moon">☾</span></button>${primary}</div></section>${body}</main></div>`;
}

async function loginPage(url, csrf, error = "") {
  return layout("登录", `<main class="login-page"><section class="login card"><div class="login-head"><div class="login-logo"><span class="mark">☁</span><strong>CloudOTP</strong></div><button class="theme-toggle" type="button" data-theme-toggle aria-label="切换日间夜间"><span class="sun">☀</span><span class="moon">☾</span></button></div><h1>登录管理后台</h1><p class="muted">登录后管理验证码和分享链接。</p>${error ? `<div class="flash error">${esc(error)}</div>` : messageBlock(url)}<form method="post"><input type="hidden" name="csrf" value="${esc(csrf)}"><label for="username">管理员账号</label><input id="username" name="username" autocomplete="username" placeholder="admin" required><label for="password">管理员密码</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="primary" style="width:100%;margin-top:18px">登录</button></form><p class="note">建议只在可信设备上登录，离开时请退出账号。</p></section></main>`);
}

function categoryOptions(categories, selected = "") {
  return categories.map((category) => `<option value="${esc(category.name)}" ${category.name === selected ? "selected" : ""}>${esc(category.name)}</option>`).join("");
}

async function dashboard(request, env, session, url) {
  const [{ results: vehicles }, { results: categories }] = await Promise.all([
    env.DB.prepare("SELECT * FROM vehicles ORDER BY code ASC").all(),
    env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all(),
  ]);
  const rows = [];
  for (const vehicle of vehicles) {
    let token = "";
    try { token = await decryptText(vehicle.share_token_cipher, env.APP_ENCRYPTION_KEY); } catch { token = "无法解密"; }
    const shareUrl = `${url.origin}/s/${token}`;
    rows.push(`<tr class="member" data-member data-name="${esc(`${vehicle.name} ${vehicle.code} ${vehicle.account} ${vehicle.category}`.toLowerCase())}" data-category="${esc(vehicle.category)}"><td data-label="账号"><div class="member-title"><span class="avatar">${esc(vehicle.name.slice(0, 1).toUpperCase() || "?")}</span><span><strong>${esc(vehicle.name)}</strong><span class="sub">${vehicle.account ? esc(vehicle.account) : "未填写账号"}${vehicle.code ? ` · ${esc(vehicle.code)}` : ""}</span></span></div></td><td data-label="标签"><span class="badge">${esc(vehicle.category)}</span></td><td data-label="验证码"><button type="button" class="totp otp-copy" data-code-id="${vehicle.id}" data-plain-code="" title="点击数字复制">••• •••</button><div class="sub" data-remaining-id="${vehicle.id}">正在获取</div></td><td data-label="分享链接"><input type="hidden" value="${esc(shareUrl)}" data-copy><div class="row-actions link-actions"><button type="button" class="copy-link" data-copy-button><span class="icon">↗</span>分享链接</button><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/rotate" onsubmit="return confirm('旧链接将立即失效，确定重置？')"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="danger reset-link"><span class="icon">↻</span>重置链接</button></form></div></td><td data-label="操作"><a class="btn edit-btn" href="/admin/vehicles/${vehicle.id}/edit" title="编辑账号"><span class="icon">✎</span>编辑</a></td></tr>`);
  }
  const options = categoryOptions(categories);
  const body = `${messageBlock(url)}<section class="card toolbar"><input id="search" placeholder="搜索账号、标签、内容..."><span class="badge"><span id="visible-count">${vehicles.length}</span> 项</span></section><section class="form-row"><div class="card form-card" id="add-account"><h2>添加账号</h2><form class="account-form" method="post" action="/admin/vehicles"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><div><label>名称</label><input name="name" required maxlength="80" placeholder="Google"></div><div><label>账号</label><input name="account" maxlength="160" placeholder="520.szxus@gmail.com"></div><div><label>编号</label><input name="code" required maxlength="20" placeholder="001"></div><div><label>标签</label><select name="category">${options}</select></div><div class="wide"><label>Base32 密钥</label><input name="secret" required autocomplete="off" placeholder="JBSWY3DPEHPK3PXP"></div><div class="wide"><label>备注</label><textarea name="notes" maxlength="2000" placeholder="保存后生成分享链接。"></textarea></div><button class="primary">保存并生成链接</button></form></div><div class="card form-card compact-card" id="add-label"><h2>添加标签</h2><form method="post" action="/admin/categories"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>标签名称</label><input name="name" required maxlength="80" placeholder="工作"><label>颜色</label><select name="color"><option value="green">绿色</option><option value="blue">蓝色</option><option value="orange">橙色</option><option value="purple">紫色</option><option value="gray">灰色</option></select><button class="primary" style="margin-top:14px">添加标签</button></form></div></section><section class="card table-card"><div class="table-head"><h2>账号列表</h2><span class="sub">点击验证码数字可复制 · 每 30 秒自动更新</span></div><div class="table-wrap">${rows.length ? `<table><thead><tr><th>账号</th><th>标签</th><th>验证码</th><th>分享链接</th><th>编辑账号</th></tr></thead><tbody id="members">${rows.join("")}</tbody></table>` : `<div class="empty"><strong>还没有账号</strong><br>先在上方添加第一个 TOTP 账号。</div>`}</div></section>`;
  const content = adminShell("/admin", "账号与验证码", "搜索、添加账号、添加标签和管理验证码。", body, session);
  return layout("管理看板", content, session).replace("</body>", `<script>
const search=document.querySelector('#search'),members=[...document.querySelectorAll('[data-member]')],count=document.querySelector('#visible-count');function apply(){const q=search.value.trim().toLowerCase();let n=0;for(const el of members){const show=!q||el.dataset.name.includes(q);el.hidden=!show;if(show)n++}count.textContent=n}search.addEventListener('input',apply);
function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}
async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}
document.addEventListener('click',async e=>{const linkBtn=e.target.closest('[data-copy-button]'),codeBtn=e.target.closest('.otp-copy');if(!linkBtn&&!codeBtn)return;const member=e.target.closest('.member');if(linkBtn){const input=member.querySelector('[data-copy]');await copyText(input.value);linkBtn.innerHTML='<span class="icon">✓</span>已复制';toast('分享链接已复制');setTimeout(()=>linkBtn.innerHTML='<span class="icon">↗</span>分享链接',1200)}if(codeBtn){const code=codeBtn.dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);codeBtn.textContent='已复制';toast('验证码已复制');setTimeout(()=>codeBtn.textContent=code.slice(0,3)+' '+code.slice(3),900)}});
async function codes(){try{const r=await fetch('/api/admin/codes',{cache:'no-store'});if(!r.ok)return;for(const item of await r.json()){const code=document.querySelector('[data-code-id="'+item.id+'"]'),left=document.querySelector('[data-remaining-id="'+item.id+'"]');if(code){code.textContent=item.code.slice(0,3)+' '+item.code.slice(3);code.dataset.plainCode=item.code}if(left)left.textContent=item.remaining+' 秒后更新'}}catch{}}codes();setInterval(codes,1000);
</script></body>`);
}

async function editAccountPage(env, session, id, url) {
  const [{ results: categories }, vehicle] = await Promise.all([
    env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all(),
    env.DB.prepare("SELECT * FROM vehicles WHERE id = ?").bind(id).first(),
  ]);
  if (!vehicle) return response(layout("未找到", `<main class="share card"><h1>账号不存在</h1><p class="muted">这个账号可能已经被删除。</p></main>`, session), 404);
  const options = categoryOptions(categories, vehicle.category);
  const body = `${messageBlock(url)}<section class="card form-card edit-card"><h2>编辑账号</h2><form method="post" action="/admin/vehicles/${vehicle.id}/edit"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>名称</label><input name="name" required maxlength="80" value="${esc(vehicle.name)}"><label>账号</label><input name="account" maxlength="160" value="${esc(vehicle.account || "")}"><div class="form-split"><div><label>编号</label><input name="code" required maxlength="20" value="${esc(vehicle.code)}"></div><div><label>标签</label><select name="category">${options}</select></div></div><label>Base32 密钥</label><input name="secret" autocomplete="off" placeholder="不修改密钥就留空"><label>备注</label><textarea name="notes" maxlength="2000">${esc(vehicle.notes || "")}</textarea><div class="row-actions" style="margin-top:14px"><button class="primary">保存修改</button><a class="btn" href="/admin">返回列表</a></div></form></section>`;
  return response(layout("编辑账号", adminShell("/admin", "编辑账号", "修改名称、账号、编号、标签和密钥。", body, session), session));
}

async function sharePage(env, vehicle, token) {
  return layout("查看验证码", `<main class="share-shell"><button class="theme-toggle share-theme" type="button" data-theme-toggle aria-label="切换日间夜间"><span class="sun">☀</span><span class="moon">☾</span></button><section class="share card"><span class="badge neutral">${esc(vehicle.category)} · 分享链接</span><h1>${esc(vehicle.name)}</h1><p class="muted">编号 ${esc(vehicle.code)}${vehicle.account ? ` · ${esc(vehicle.account)}` : ""}</p><button type="button" class="totp otp-copy share-otp" id="code" data-plain-code="">••• •••</button><p class="muted"><span id="remaining">--</span> 秒后更新</p><div class="bar"><i id="bar" style="width:100%"></i></div><p class="note">点击验证码数字即可复制。验证码属于敏感凭据，请勿截图或转发本页面。</p></section></main><script>function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}document.querySelector('#code').addEventListener('click',async()=>{const el=document.querySelector('#code');const code=el.dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);el.textContent='已复制';toast('验证码已复制');setTimeout(()=>el.textContent=code.slice(0,3)+' '+code.slice(3),900)});async function update(){try{const r=await fetch('/api/s/${esc(token)}/code',{cache:'no-store'});if(!r.ok)throw 0;const d=await r.json();const el=document.querySelector('#code');el.textContent=d.code.slice(0,3)+' '+d.code.slice(3);el.dataset.plainCode=d.code;document.querySelector('#remaining').textContent=d.remaining;document.querySelector('#bar').style.width=(d.remaining/30*100)+'%'}catch{document.querySelector('#code').textContent='链接已失效'}}update();setInterval(update,1000)</script>`);
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
  if (path === "/admin/add" && method === "GET") return redirect("/admin#add-account");
  if (path === "/admin/categories" && method === "GET") return redirect("/admin#add-label");
  if ((path === "/admin/settings" || path === "/admin/logs") && method === "GET") return redirect("/admin");

  const editMatch = path.match(/^\/admin\/vehicles\/(\d+)\/edit$/);
  if (editMatch && method === "GET") return editAccountPage(env, session, Number(editMatch[1]), url);
  if (editMatch && method === "POST") {
    try {
      const form = await formData(request, session);
      const id = Number(editMatch[1]);
      const name = String(form.get("name") || "").trim();
      const code = String(form.get("code") || "").trim();
      const category = String(form.get("category") || "未分类").trim() || "未分类";
      if (!name || !code) throw new Error("名称和编号不能为空");
      if (!await env.DB.prepare("SELECT id FROM categories WHERE name = ?").bind(category).first()) throw new Error("请选择有效分类");
      const secretValue = String(form.get("secret") || "").trim();
      if (secretValue) {
        const secret = normalizeSecret(secretValue);
        await env.DB.prepare("UPDATE vehicles SET name = ?, code = ?, category = ?, account = ?, notes = ?, secret_cipher = ? WHERE id = ?").bind(name, code, category, String(form.get("account") || "").trim(), String(form.get("notes") || "").trim(), await encryptText(secret, env.APP_ENCRYPTION_KEY), id).run();
      } else {
        await env.DB.prepare("UPDATE vehicles SET name = ?, code = ?, category = ?, account = ?, notes = ? WHERE id = ?").bind(name, code, category, String(form.get("account") || "").trim(), String(form.get("notes") || "").trim(), id).run();
      }
      return flashRedirect("/admin", "账号已更新");
    } catch (error) {
      return flashRedirect(`/admin/vehicles/${editMatch[1]}/edit`, `保存失败：${error.message.includes("UNIQUE") ? "编号已经存在" : error.message}`, "error");
    }
  }

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
      return flashRedirect("/admin", "账号已添加，专属链接已生成");
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
      return flashRedirect("/admin", "标签已添加");
    } catch (error) {
      return flashRedirect("/admin", `保存失败：${error.message.includes("UNIQUE") ? "标签已经存在" : error.message}`, "error");
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
    return flashRedirect("/admin", action === "rotate" ? "已生成新链接，旧链接立即失效" : action === "delete" ? "账号已删除" : "分享状态已更新");
  }

  if (path === "/api/admin/codes" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, secret_cipher, enabled FROM vehicles ORDER BY code ASC").all();
    const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    return json(await Promise.all(results.map(async (row) => ({ id: row.id, enabled: Boolean(row.enabled), code: await totp(await decryptText(row.secret_cipher, env.APP_ENCRYPTION_KEY)), remaining }))));
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
