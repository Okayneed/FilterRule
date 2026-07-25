// ==UserScript==
// @name         代理分流规则检测器
// @namespace    https://github.com/Okayneed/FilterRule
// @version      2.0.0
// @description  自动检测当前域名及页面内加载的子域名是否命中 GitHub 托管的代理分流规则
// @author       Okayneed
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setClipboard
// @connect      raw.githubusercontent.com
// @connect      api.github.com
// @run-at       document-end
// ==/UserScript==

(function () {
  'use strict';

  // ======================== 配置区 ========================

  const CONFIG = {

    // --- 规则源（仅 QX，LOON 保持一致不重复对比）---
    ruleSources: [
      { name: "GFW-Auto",    type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Auto_gfw.list",     enabled: true },
      { name: "goProxy",     type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goProxy.list", enabled: true },
      { name: "goJP",        type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goJP.list",    enabled: true },
      { name: "goUS",        type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goUS.list",    enabled: true },
    ],

    // --- 默认输出模式 ---
    outputMode: "loon",                // "loon" | "qx"
    defaultRuleType: "DOMAIN-SUFFIX",  // "DOMAIN-SUFFIX" | "DOMAIN" | "DOMAIN-KEYWORD"
    defaultPolicy: "Proxy",

    // --- GitHub 写入（默认开启） ---
    githubWrite: {
      enabled: true,
      owner: "Okayneed",
      repo: "FilterRule",
      branch: "main",
      filePath: "list/Manual_ManualSetting.list",
      token: "",  // <--- 填入你的 GitHub token
    },

    // --- 调试 ---
    debug: false,
  };

  // ======================== 图标 ========================
  const ICON_PROXY = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAARQ0lEQVR4nO1dfawdRRU/e+97D2wL5QGC5ctCP4SCIQbDh8hHImBipAp9Cd/IH0ojCqmo0aB/IBqDJiYiARMFNUWUEDUoYksCQtEiRqBi2mJFoaEt2ALtg9JC37v3rpn4+yWHyc5+3Lt77+zt/JLN3bu7Mzs758zMOWfOmREJCAgICAgICAjY6xBVmFdcYt4BnqIhIiP4LXIvoOY9AInaUddGReRdOH9LRKYzng+oKQM0RaSN84Ui8gkROVtE5ovIOK7vEJHnReQREfmtiGxISBtQQxgCGswTkeVo6XHG8baI/FxEFlh5BNQMJNxlaOEksOnqW2jZHRxtXJtWz02KyBVWXgE1AQl2vUX4To4eoGMxwhetPAM8Bwl1KQjI1h4XPNqKES618g7wFA0IikeLyE4QMY34HALSmKCNvOYi76Amegy20F+obj+NsK7/+mAed1vvCPAMbJlGep9Kadma0DtxJN2ze4oppRmEXmBAaOS4twRGniT9PcZza/HcQhzmfD3uJZmE28jzwhzlCBgQSJSVSvizW34HhD4wIf1BIrJOqYU6LfNaYb0rwDMLoWmlzzm6c/43lkCDfZAuwrnB4oy0/8I79DsDPACJsb+IbFPjth7DOeYfogiv05vjUCUTJKXfhnfodwb0EVldr03YslF1/gE9MsBumHDFEuYitOJZInIq7o0pgo7h2ql4pmMRmnlN4h0BNRcCD3YIgeszhMCV1rsCPFQDH8Vv7Lh/nIg8JiITIjIHxwSuHed4D/N6JEc5AgYEEsXM8+9RLb5XQxB7hD3IW78rwDPQTLu8AlPwcusddUbkOIZmMugoCGydEiaDOsjrqBpOBkVg2BEczRyELvq8d2ALXVLCdDCFvyVW3j6joYjnwhi0nQNEZDbOx3LkOXDmz8uN9OX7rIjcjmutnBxN4psPNrhGRH7ouX9gpOYxtCPrfhBs...";

  // ======================== 内部状态 ========================
  const STATE = {
    rules: [],
    loading: false,
    allFetched: false,
    domains: [],        // [{domain, label, matched: rule|null}]
    iconPos: { x: 8, y: 120 },
  };

  // ======================== 工具函数 ========================
  function log(...args) { if (CONFIG.debug) console.log("[RuleChecker]", ...args); }
  function warn(...args) { console.warn("[RuleChecker]", ...args); }

  function getCleanDomain(host) {
    if (host.startsWith("www.")) host = host.slice(4);
    return host;
  }

  function extractHostname(url) {
    try {
      return new URL(url).hostname;
    } catch (_) {
      return "";
    }
  }

  // ======================== 规则解析 ========================
  const QX_MAP = { "host":"DOMAIN","host-suffix":"DOMAIN-SUFFIX","host-keyword":"DOMAIN-KEYWORD","host-wildcard":"DOMAIN-SUFFIX" };
  const LOON_MAP = { "DOMAIN":"DOMAIN","DOMAIN-SUFFIX":"DOMAIN-SUFFIX","DOMAIN-KEYWORD":"DOMAIN-KEYWORD",
    "HOST":"DOMAIN","HOST-SUFFIX":"DOMAIN-SUFFIX","HOST-KEYWORD":"DOMAIN-KEYWORD","IP-CIDR":"IP-CIDR","GEOIP":"GEOIP","IP-CIDR6":"IP-CIDR" };

  function parseLine(line, sourceType) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!") || trimmed.startsWith("//")) return null;
    const map = sourceType === "qx" ? QX_MAP : LOON_MAP;
    const idx = trimmed.indexOf(",");
    if (idx === -1) return null;
    const rawKey = trimmed.slice(0, idx).trim().toUpperCase();
    const value = trimmed.slice(idx + 1).trim();
    if (!value) return null;
    const lookupKey = sourceType === "qx" ? rawKey.toLowerCase() : rawKey;
    const mappedType = map[lookupKey];
    if (!mappedType) return null;
    let finalValue = value;
    if (lookupKey === "host-wildcard" && finalValue.startsWith(".")) finalValue = finalValue.slice(1);
    return { type: mappedType, value: finalValue };
  }

  function parseRules(text, sourceType) {
    const rules = [];
    for (const line of text.split(/\r?\n/)) {
      const p = parseLine(line, sourceType);
      if (p) rules.push(p);
    }
    return rules;
  }

  // ======================== 规则匹配 ========================
  function matchRule(domain, rule) {
    const d = domain.toLowerCase(), v = rule.value.toLowerCase();
    switch (rule.type) {
      case "DOMAIN": return d === v;
      case "DOMAIN-SUFFIX": return d === v || d.endsWith("." + v);
      case "DOMAIN-KEYWORD": return d.includes(v);
    }
    return false;
  }

  function findMatch(domain) {
    for (const rule of STATE.rules) {
      if (matchRule(domain, rule)) return rule;
    }
    return null;
  }

  // ======================== 规则拉取 ========================
  function fetchRuleSource(source) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: "GET", url: source.rawUrl, timeout: 15000,
        onload(r) {
          if (r.status >= 200 && r.status < 300) { log(`[${source.name}] OK, ${r.responseText.length}B`); resolve(r.responseText); }
          else { warn(`[${source.name}] HTTP ${r.status}`); reject(new Error(`HTTP ${r.status}`)); }
        },
        onerror(e) { warn(`[${source.name}] 网络错误`); reject(e); },
        ontimeout() { warn(`[${source.name}] 超时`); reject(new Error("timeout")); },
      });
    });
  }

  async function fetchAllRules() {
    if (STATE.loading) return;
    STATE.loading = true; STATE.rules = [];
    const enabled = CONFIG.ruleSources.filter(s => s.enabled);
    log(`拉取 ${enabled.length} 个源...`);
    await Promise.allSettled(enabled.map(async src => {
      try {
        const text = await fetchRuleSource(src);
        const parsed = parseRules(text, src.type);
        parsed.forEach(r => { r.source = src.name; r.rawLine = `${r.type},${r.value}`; });
        STATE.rules.push(...parsed);
        log(`[${src.name}] ${parsed.length} 条`);
      } catch (e) { warn(`[${src.name}] 跳过: ${e.message}`); }
    }));
    STATE.allFetched = true; STATE.loading = false;
    log(`加载完成, ${STATE.rules.length} 条`);
  }

  // ======================== 域名收集与检测 ========================
  function collectDomains() {
    const seen = new Set();
    const entries = [];

    function add(host, label) {
      const d = getCleanDomain(host);
      if (!d || seen.has(d)) return;
      seen.add(d);
      entries.push({ domain: d, label: label, matched: findMatch(d) });
    }

    // 主域名
    add(window.location.hostname, "主域名");

    // iframe 子域名
    document.querySelectorAll("iframe").forEach(iframe => {
      try {
        const src = iframe.src || iframe.getAttribute("src") || "";
        if (src) {
          const h = extractHostname(src);
          if (h && h !== window.location.hostname) add(h, "iframe");
        }
      } catch (_) {}
    });

    STATE.domains = entries;
  }

  function hasAnyHit() {
    return STATE.domains.some(d => d.matched !== null);
  }

  function isAllDirect() {
    return STATE.allFetched && STATE.domains.length > 0 && STATE.domains.every(d => d.matched === null);
  }

  function isAllProxy() {
    return STATE.allFetched && STATE.domains.length > 0 && STATE.domains.every(d => d.matched !== null);
  }

  // ======================== 建议规则 ========================
  function generateSuggestedRule(domain) {
    const mode = CONFIG.outputMode, rt = CONFIG.defaultRuleType;
    if (mode === "loon") return { line: `${rt},${domain}`, policy: CONFIG.defaultPolicy };
    const qxType = rt.replace("DOMAIN","host").replace("-SUFFIX","-suffix").replace("-KEYWORD","-keyword");
    return { line: `${qxType}, ${domain}`, policy: CONFIG.defaultPolicy };
  }

  // ======================== 复制 ========================
  function copyRule(domain) {
    const s = generateSuggestedRule(domain);
    if (!s) return;
    GM_setClipboard(s.line, "text");
    showToast("已复制: " + s.line);
  }

  // ======================== GitHub 写入 ========================
  const GitHubWriter = {
    async getFileSha() {
      const gw = CONFIG.githubWrite;
      const url = `https://api.github.com/repos/${gw.owner}/${gw.repo}/contents/${gw.filePath}?ref=${gw.branch}`;
      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: "GET", url,
          headers: { Authorization: `token ${gw.token}`, Accept: "application/vnd.github.v3+json" },
          onload(r) {
            if (r.status === 200) {
              const d = JSON.parse(r.responseText);
              resolve({ sha: d.sha, content: atob(d.content.replace(/\n/g,"")) });
            } else reject(new Error(`HTTP ${r.status}`));
          },
          onerror: reject,
        });
      });
    },

    async appendRule(ruleLine, domain) {
      const gw = CONFIG.githubWrite;
      if (!gw.token) { showToast("请先在脚本配置中填入 GitHub token", "error"); return; }

      try {
        const { sha, content } = await this.getFileSha();
        if (content.includes(ruleLine)) { showToast("规则已存在，跳过", "warn"); return; }

        const newContent = content.trimEnd() + "\n" + ruleLine + "\n";
        const encoded = btoa(unescape(encodeURIComponent(newContent)));
        const url = `https://api.github.com/repos/${gw.owner}/${gw.repo}/contents/${gw.filePath}`;

        await new Promise((resolve, reject) => {
          GM_xmlhttpRequest({
            method: "PUT", url,
            headers: { Authorization: `token ${gw.token}`, Accept: "application/vnd.github.v3+json", "Content-Type":"application/json" },
            data: JSON.stringify({ message: `[auto] add rule: ${ruleLine}`, content: encoded, sha, branch: gw.branch }),
            onload(r) { (r.status === 200 || r.status === 201) ? resolve(JSON.parse(r.responseText)) : reject(new Error(`HTTP ${r.status}`)); },
            onerror: reject,
          });
        });

        showToast("已提交: " + ruleLine);

        // 更新本地
        STATE.rules.push({ type: CONFIG.defaultRuleType, value: domain, source: `${gw.owner}/${gw.repo}`, rawLine: ruleLine });
        collectDomains();
        updateFloatingIcon();
        renderPanelIfOpen();
      } catch (e) {
        showToast("提交失败: " + e.message, "error");
        warn("GitHub 写入失败:", e);
      }
    },
  };

  function submitRule(domain) {
    const s = generateSuggestedRule(domain);
    if (s) GitHubWriter.appendRule(s.line, domain);
  }

  // ======================== Toast ========================
  function showToast(msg, type) {
    const old = document.getElementById("rc-toast"); if (old) old.remove();
    const bg = type === "error" ? "#e74c3c" : type === "warn" ? "#f39c12" : "#27ae60";
    const t = document.createElement("div"); t.id = "rc-toast";
    t.style.cssText = `position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:${bg};color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;z-index:2147483647;box-shadow:0 4px 16px rgba(0,0,0,.2);pointer-events:none;transition:opacity .3s;opacity:1;`;
    t.textContent = msg; document.body.appendChild(t);
    setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 300); }, 2500);
  }

  // ======================== 浮动图标 ========================
  function getIconColor() {
    if (!STATE.allFetched) return { bg: "#45475a", label: "#f9e2af" };
    if (hasAnyHit()) return { bg: "#45475a", label: "#a6e3a1" };
    return { bg: "#45475a", label: "#f38ba8" };
  }

  function getIconLetter() {
    if (!STATE.allFetched) return "…";
    // 主域名是否命中来决定 P/D（取主域名判断）
    const main = STATE.domains.find(d => d.label === "主域名");
    if (!main) return "?";
    return main.matched ? "P" : "D";
  }

  function createFloatingIcon() {
    const old = document.getElementById("rc-floating-icon"); if (old) old.remove();
    const { bg, label } = getIconColor();
    const letter = getIconLetter();
    const x = STATE.iconPos.x, y = STATE.iconPos.y;

    const icon = document.createElement("div");
    icon.id = "rc-floating-icon";
    icon.title = (STATE.domains.map(d =>
      `${d.label}: ${d.domain} → ${d.matched ? "PROXY" : "DIRECT"}`
    ).join("\n")) || "加载中…";

    icon.style.cssText = `position:fixed;z-index:2147483645;top:${y}px;right:${x}px;width:40px;height:40px;border-radius:50%;background:${bg};color:${label};display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 12px rgba(0,0,0,.35);transition:transform .15s,box-shadow .15s;user-select:none;font-weight:700;font-size:18px;font-family:-apple-system,sans-serif;`;

    // 字母 P/D
    const letterEl = document.createElement("span");
    letterEl.textContent = letter;
    letterEl.style.cssText = "position:relative;z-index:1;";
    icon.appendChild(letterEl);

    // 点击
    icon.addEventListener("click", function(e) {
      if (icon._dragged) return;
      togglePanel();
    });

    // 拖动
    let dragging = false, startX, startY, startRight, startTop;
    icon.addEventListener("mousedown", function(e) {
      dragging = true; icon._dragged = false;
      startX = e.clientX; startY = e.clientY;
      startRight = parseInt(icon.style.right) || 8; startTop = parseInt(icon.style.top) || 120;
      icon.style.transition = "none"; e.preventDefault();
    });
    document.addEventListener("mousemove", function(e) {
      if (!dragging) return;
      const dx = startX - e.clientX, dy = e.clientY - startY;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) icon._dragged = true;
      icon.style.right = Math.max(4, Math.min(window.innerWidth - 44, startRight + dx)) + "px";
      icon.style.top = Math.max(4, Math.min(window.innerHeight - 44, startTop + dy)) + "px";
    });
    document.addEventListener("mouseup", function() {
      if (dragging) {
        dragging = false; icon.style.transition = "transform .15s,box-shadow .15s";
        STATE.iconPos = { x: parseInt(icon.style.right)||8, y: parseInt(icon.style.top)||120 };
      }
    });
    // 触摸
    icon.addEventListener("touchstart", function(e) {
      dragging = true; icon._dragged = false;
      const t = e.touches[0]; startX = t.clientX; startY = t.clientY;
      startRight = parseInt(icon.style.right)||8; startTop = parseInt(icon.style.top)||120;
      icon.style.transition = "none";
    }, {passive:false});
    document.addEventListener("touchmove", function(e) {
      if (!dragging) return;
      const t = e.touches[0], dx = startX - t.clientX, dy = t.clientY - startY;
      if (Math.abs(dx)>2||Math.abs(dy)>2) icon._dragged = true;
      icon.style.right = Math.max(4, Math.min(window.innerWidth-44, startRight+dx)) + "px";
      icon.style.top = Math.max(4, Math.min(window.innerHeight-44, startTop+dy)) + "px";
    }, {passive:false});
    document.addEventListener("touchend", function() {
      if (dragging) { dragging = false; icon.style.transition = "transform .15s,box-shadow .15s";
        STATE.iconPos = { x: parseInt(icon.style.right)||8, y: parseInt(icon.style.top)||120 }; }
    });
    icon.addEventListener("mouseenter", function() { icon.style.transform="scale(1.1)"; icon.style.boxShadow="0 4px 20px rgba(0,0,0,.4)"; });
    icon.addEventListener("mouseleave", function() { icon.style.transform="scale(1)"; icon.style.boxShadow="0 2px 12px rgba(0,0,0,.35)"; });

    document.body.appendChild(icon);
  }

  function updateFloatingIcon() {
    const icon = document.getElementById("rc-floating-icon");
    if (!icon) return createFloatingIcon();
    const { bg, label } = getIconColor();
    const letter = getIconLetter();
    icon.style.background = bg;
    icon.style.color = label;
    const span = icon.querySelector("span");
    if (span) span.textContent = letter;
    icon.title = (STATE.domains.map(d =>
      `${d.label}: ${d.domain} → ${d.matched ? "PROXY" : "DIRECT"}`
    ).join("\n")) || "加载中…";
  }

  // ======================== 面板 ========================
  function togglePanel() {
    const panel = document.getElementById("rule-checker-panel");
    if (panel) { panel.remove(); return; }
    createPanel();
  }

  function collapsePanel() {
    const panel = document.getElementById("rule-checker-panel");
    if (panel) panel.remove();
  }

  function createPanel() {
    const old = document.getElementById("rule-checker-panel"); if (old) old.remove();
    const gw = CONFIG.githubWrite;

    const panel = document.createElement("div");
    panel.id = "rule-checker-panel";
    panel.style.cssText = `position:fixed;top:16px;right:16px;z-index:2147483646;width:300px;max-height:calc(100vh-32px);background:#1e1e2e;color:#cdd6f4;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.45);font-family:-apple-system,"SF Pro Text","Helvetica Neue",sans-serif;font-size:11px;overflow:hidden;display:flex;flex-direction:column;user-select:none;`;
    panel.innerHTML = buildPanelHTML();
    document.body.appendChild(panel);
    bindPanelEvents(panel);
  }

  function buildPanelHTML() {
    const gw = CONFIG.githubWrite;
    let domainRows = "";
    STATE.domains.forEach((d, i) => {
      const hit = d.matched;
      const color = hit ? "#a6e3a1" : "#f38ba8";
      const status = hit ? "P" : "D";
      const suggested = (!hit && STATE.allFetched) ? generateSuggestedRule(d.domain) : null;
      domainRows += `
        <div style="margin-bottom:6px;background:#181825;border-radius:8px;padding:8px 10px;border-left:3px solid ${color};">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
            <span style="font-size:10px;color:#6c7086;">${escapeHTML(d.label)}</span>
            <span style="font-weight:700;font-size:12px;color:${color};">${status}</span>
          </div>
          <div style="color:#89b4fa;font-weight:600;font-size:12px;word-break:break-all;margin-bottom:2px;">${escapeHTML(d.domain)}</div>
          ${hit ? `
          <div style="font-size:10px;color:#9399b2;">${escapeHTML(hit.rawLine)} · ${escapeHTML(hit.source)}</div>
          ` : (STATE.allFetched ? `
          <div style="font-size:10px;color:#f9e2af;margin-bottom:4px;">建议: ${escapeHTML(suggested.line)}</div>
          <div style="display:flex;gap:4px;">
            <button class="rc-copy-btn" data-domain="${escapeHTML(d.domain)}" style="background:#45475a;color:#cdd6f4;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;font-size:10px;font-family:inherit;">📋 复制</button>
            <button class="rc-submit-btn" data-domain="${escapeHTML(d.domain)}" style="background:${gw.token?'#cba6f7':'#313244'};color:${gw.token?'#1e1e2e':'#6c7086'};border:none;border-radius:4px;padding:3px 8px;cursor:${gw.token?'pointer':'not-allowed'};font-size:10px;font-family:inherit;" ${gw.token?'':'disabled'}>🚀 提交</button>
          </div>
          ` : '<div style="font-size:10px;color:#6c7086;">规则加载中…</div>')}
        </div>`;
    });

    return `
      <div style="padding:10px 12px;background:#181825;border-bottom:1px solid #313244;display:flex;justify-content:space-between;align-items:center;gap:8px;">
        <span style="display:flex;align-items:center;gap:6px;">
          <img src="${ICON_PROXY}" style="width:18px;height:18px;">
          <span style="font-weight:700;font-size:12px;color:#cba6f7;">分流规则检测</span>
        </span>
        <div style="display:flex;gap:4px;">
          <button id="rc-refresh" title="刷新" style="background:none;border:1px solid #45475a;color:#a6adc8;cursor:pointer;border-radius:4px;padding:1px 5px;font-size:10px;">🔄</button>
          <button id="rc-close" title="关闭" style="background:none;border:1px solid #45475a;color:#a6adc8;cursor:pointer;border-radius:4px;padding:1px 5px;font-size:10px;">✕</button>
        </div>
      </div>
      <div style="padding:10px 12px;overflow-y:auto;flex:1;">
        ${domainRows || '<div style="color:#6c7086;font-size:11px;">未检测到域名</div>'}
        <div style="font-size:10px;color:#585b70;margin-top:4px;">${STATE.rules.length} 条规则${STATE.loading?' · 加载中…':''}</div>
      </div>`;
  }

  function escapeHTML(str) {
    const el = document.createElement("span"); el.textContent = str; return el.innerHTML;
  }

  function bindPanelEvents(panel) {
    panel.querySelector("#rc-refresh")?.addEventListener("click", async function() {
      this.textContent = "⏳"; this.disabled = true;
      STATE.allFetched = false;
      await fetchAllRules();
      collectDomains();
      updateFloatingIcon();
      renderPanelIfOpen();
    });
    panel.querySelector("#rc-close")?.addEventListener("click", collapsePanel);

    panel.querySelectorAll(".rc-copy-btn").forEach(btn => {
      btn.addEventListener("click", function() { copyRule(this.dataset.domain); });
    });
    panel.querySelectorAll(".rc-submit-btn").forEach(btn => {
      btn.addEventListener("click", function() { submitRule(this.dataset.domain); });
    });
  }

  function renderPanelIfOpen() {
    const panel = document.getElementById("rule-checker-panel");
    if (!panel) return;
    panel.innerHTML = buildPanelHTML();
    bindPanelEvents(panel);
  }

  // ======================== iframe 监听 ========================
  function watchIframes() {
    const observer = new MutationObserver(() => {
      collectDomains();
      updateFloatingIcon();
      renderPanelIfOpen();
    });
    observer.observe(document.body, { childList: true, subtree: true });
    // 也监听 iframe 的 src 变化
    setInterval(() => {
      const prev = STATE.domains.length;
      collectDomains();
      if (STATE.domains.length !== prev) {
        updateFloatingIcon();
        renderPanelIfOpen();
      }
    }, 3000);
  }

  // ======================== 初始化 ========================
  async function init() {
    log("脚本初始化...");
    collectDomains();
    createFloatingIcon();

    await fetchAllRules();
    collectDomains();
    updateFloatingIcon();

    watchIframes();
    log("初始化完成");
  }

  init();
})();
