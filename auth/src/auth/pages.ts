/** Local authorization presentation with escaped dynamic text. */
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]!);
function document(title: string, body: string) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · DotSignal for ChatGPT</title><style>body{font:16px/1.65 system-ui;background:#f5f6f8;color:#18212f;margin:0;padding:48px 20px}main{max-width:480px;margin:auto;background:white;padding:32px;border:1px solid #ddd;border-radius:12px}button{padding:12px 20px;margin:8px 8px 0 0}code{overflow-wrap:anywhere}</style></head><body><main>${body}</main></body></html>`;
}
export function renderConsentPage(input: { displayName: string; uid: string; csrf: string; scopes?: string[] }) {
  const scopes = input.scopes ?? ['feishu:read'];
  const hasFeishu = scopes.includes('feishu:read'), hasMail = scopes.includes('mail:read');
  const title = hasMail ? '允许 Dot 监测企业邮箱？' : '允许 Dot 读取飞书？';
  const permissions = [
    hasFeishu ? '<li><strong>feishu:read</strong>：读取已授权的飞书信息，并管理飞书事件订阅。</li>' : '',
    hasMail ? '<li><strong>mail:read</strong>：监测网易企业邮箱邮件头（发件人、主题、时间等）并管理新邮件事件订阅；不读取邮件正文或附件。</li>' : '',
  ].join('');
  return document('连接云端监测', `<h1>${title}</h1><p>当前账号：${escape(input.displayName)}</p><ul>${permissions}</ul><p>不会发送消息、发送邮件或修改飞书与邮箱内容。仅授予本页列出的权限。</p><form method="post" action="/dot-feishu/auth/interaction/${escape(input.uid)}/confirm"><input type="hidden" name="csrf" value="${escape(input.csrf)}"><button name="decision" value="allow">同意并连接</button><button name="decision" value="deny">拒绝</button></form>`);
}
export function renderAuthMessage(input: { title: string; message: string; detail?: string; reference?: string; appId?: string }) {
  return document(input.title, `<h1>${escape(input.title)}</h1><p>${escape(input.message)}</p>${input.detail ? `<p>${escape(input.detail)}</p>` : ''}${input.reference ? `<p>编号：<code>${escape(input.reference)}</code></p>` : ''}`);
}
