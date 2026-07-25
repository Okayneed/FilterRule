// ==UserScript==
// @name         代理分流规则检测器
// @namespace    https://github.com/Okayneed/FilterRule
// @version      2.1.1
// @description  检测当前网页主域名是否命中代理分流规则，并显示实际延迟
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
    ruleSources: [
      { name: "GFW-Auto",    type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Auto_gfw.list",     enabled: true },
      { name: "goProxy",     type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goProxy.list", enabled: true },
      { name: "goJP",        type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goJP.list",    enabled: true },
      { name: "goUS",        type: "qx", rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goUS.list",    enabled: true },
    ],

    outputMode: "loon",
    defaultRuleType: "DOMAIN-SUFFIX",
    defaultPolicy: "Proxy",

    githubWrite: {
      enabled: true,
      owner: "Okayneed",
      repo: "FilterRule",
      branch: "main",
      filePath: "list/Manual_ManualSetting.list",
      token: "",
    },

    debug: false,
  };

  // ======================== 图标 ========================
  const ICON_PROXY = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAARQ0lEQVR4nO1dfawdRRU/e+97D2wL5QGC5ctCP4SCIQbDh8hHImBipAp9Cd/IH0ojCqmo0aB/IBqDJiYiARMFNUWUEDUoYksCQtEiRqBi2mJFoaEt2ALtg9JC37v3rpn4+yWHyc5+3Lt77+zt/JLN3bu7Mzs758zMOWfOmREJCAgICAgICAjY6xBVmFdcYt4BnqIhIiP4LXIvoOY9AInaUddGReRdOH9LRKYzng+oKQM0RaSN84Ui8gkROVtE5ovIOK7vEJHnReQREfmtiGxISBtQQxgCGswTkeVo6XHG8baI/FxEFlh5BNQMJNxlaOEksOnqW2jZHRxtXJtWz02KyBVWXgE1AQl2vUX4To4eoGMxwhetPAM8Bwl1KQjI1h4XPNqKES618g7wFA0IikeLyE4QMY34HALSmKCNvOYi76Amegy20F+obj+NsK7/+mAed1vvCPAMbJlGep9Kadma0DtxJN2ze4oppRmEXmBAaOS4twRGniT9PcZza/HcQhzmfD3uJZmE28jzwhzlCBgQSJSVSvizW34HhD4wIf1BIrJOqYU6LfNaYb0rwDMLoWmlzzm6c/43lkCDfZAuwrnB4oy0/8I79DsDPACJsb+IbFPjth7DOeYfogiv05vjUCUTJKXfhnfodwb0EVldr03YslF1/gE9MsBumHDFEuYitOJZInIq7o0pgo7h2ql4pmMRmnlN4h0BNRcCD3YIgeszhMCV1rsCPFQDH8Vv7Lh/nIg8JiITIjIHxwSuHed4D/N6JEc5AgYEEsXM8+9RLb5XQxB7hD3IW78rwDPQTLu8AlPwcusddUbkOIZmMugoCGydEiaDOsjrqBpOBkVg2BEczRyELvq8d2ALXVLCdDCFvyVW3j6joYjnwhi0nQNEZDbOx3LkOXDmz8uN9OX7rIjcjmutnBxN4psPNrhGRH7ouX9gpOYxtCPrfhBs...";

  // ======================== 内部状态 ========================
  const STATE = {
    rules: [],
    loading: false,
    allFetched: false,
    domain: "",
    matched: null,      // 命中的规则，null=未命中/未检测
    latencyMs: null,    // 延迟（毫秒）
  };

  // ======================== 工具函数 ========================
  function log(...args) { if (CONFIG.debug) console.log("[RuleChecker]", ...args); }
  function warn(...args) { console.warn("[RuleChecker]", ...args); }

  function getCleanDomain() {
    let host = window.location.hostname;
    if (host.startsWith("www.")) host = host.slice(4);
    return host;
  }

  // ======================== 延迟测量 ========================
  // 使用 Navigation Timing API 获取页面真实加载延迟（零额外请求）
  function measureLatency() {
    try {
      // 优先用 Navigation Timing Level 2
      const entries = performance.getEntriesByType("navigation");
      if (entries && entries.length > 0) {
        const nav = entries[0];
        // TTFB = 服务器首字节时间，最能反映代理延迟
        const ttfb = nav.responseStart - nav.requestStart;
        if (ttfb > 0 && ttfb < 60000) { STATE.latencyMs = Math.round(ttfb); return; }
        // 回退：TCP 连接时间
        const tcp = nav.connectEnd - nav.connectStart;
        if (tcp > 0 && tcp < 60000) { STATE.latencyMs = Math.round(tcp); return; }
      }
      // 回退到 Level 1
      const t = performance.timing;
      if (t && t.responseStart > 0 && t.requestStart > 0) {
        const ttfb = t.responseStart - t.requestStart;
        if (ttfb > 0 && ttfb < 60000) { STATE.latencyMs = Math.round(ttfb); return; }
      }
    } catch (_) {}
    STATE.latencyMs = null;
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

  // ======================== 域名检测（仅主域名） ========================
  function checkDomain() {
    STATE.domain = getCleanDomain();
    STATE.matched = STATE.domain ? findMatch(STATE.domain) : null;
  }

  // ======================== 建议规则 ========================
  function generateSuggestedRule() {
    const d = STATE.domain;
    if (!d) return null;
    // 根据写入目标文件路径自动判断格式：list/ → QX，loon-rule/ → LOON
    const fp = CONFIG.githubWrite.filePath;
    const isQX = fp.startsWith("list/");
    const rt = CONFIG.defaultRuleType;
    const policy = CONFIG.defaultPolicy;

    if (isQX) {
      // QX: host-suffix, example.com, Proxy
      const qxType = rt.replace("DOMAIN","host").replace("-SUFFIX","-suffix").replace("-KEYWORD","-keyword");
      return { line: `${qxType}, ${d}, ${policy}`, policy };
    } else {
      // LOON: DOMAIN-SUFFIX,example.com,Proxy
      return { line: `${rt},${d},${policy}`, policy };
    }
  }

  // ======================== 复制 ========================
  function copyRule() {
    const s = generateSuggestedRule();
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

    async appendRule(ruleLine) {
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

        // 更新本地状态
        STATE.rules.push({ type: CONFIG.defaultRuleType, value: STATE.domain, source: `${gw.owner}/${gw.repo}`, rawLine: ruleLine });
        STATE.matched = STATE.rules[STATE.rules.length - 1];
        updateFloatingIcon();
        renderPanelIfOpen();
      } catch (e) {
        showToast("提交失败: " + e.message, "error");
        warn("GitHub 写入失败:", e);
      }
    },
  };

  function submitRule() {
    const s = generateSuggestedRule();
    if (s) GitHubWriter.appendRule(s.line, STATE.domain);
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

  // ======================== 浮动图标 + 延迟显示 ========================
  function getIconStyle() {
    if (!STATE.allFetched) return { color: "#f9e2af", letter: "…" };
    if (STATE.matched) return { color: "#a6e3a1", letter: "P" };
    return { color: "#f38ba8", letter: "D" };
  }

  function createFloatingIcon() {
    const old = document.getElementById("rc-floating-icon"); if (old) old.remove();
    const { color, letter } = getIconStyle();
    const x = STATE.iconPos?.x || 8, y = STATE.iconPos?.y || 120;

    const wrapper = document.createElement("div");
    wrapper.id = "rc-floating-icon";
    wrapper.style.cssText = `position:fixed;z-index:2147483645;top:${y}px;right:${x}px;display:flex;flex-direction:column;align-items:center;gap:2px;user-select:none;`;

    // 圆形按钮
    const circle = document.createElement("div");
    circle.className = "rc-circle";
    circle.style.cssText = `width:40px;height:40px;border-radius:50%;background:#45475a;color:${color};display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 12px rgba(0,0,0,.35);transition:transform .15s,box-shadow .15s;font-weight:700;font-size:18px;font-family:-apple-system,sans-serif;`;
    circle.textContent = letter;
    circle.title = [
      STATE.domain || "(无域名)",
      STATE.allFetched
        ? (STATE.matched ? `PROXY · ${STATE.matched.rawLine}` : "DIRECT")
        : "加载中…",
      STATE.latencyMs != null ? `延迟 ${STATE.latencyMs}ms` : "",
    ].filter(Boolean).join("\n");

    // 延迟文字
    const latencyLabel = document.createElement("div");
    latencyLabel.className = "rc-latency";
    const latText = STATE.latencyMs != null ? `${STATE.latencyMs}ms` : "—";
    latencyLabel.textContent = latText;
    latencyLabel.style.cssText = `color:#a6adc8;font-size:9px;font-family:-apple-system,sans-serif;text-align:center;line-height:1;text-shadow:0 1px 4px rgba(0,0,0,.6);`;

    wrapper.appendChild(circle);
    wrapper.appendChild(latencyLabel);
    document.body.appendChild(wrapper);

    // 点击切换面板
    circle.addEventListener("click", function(e) {
      if (circle._dragged) return;
      togglePanel();
    });

    // 拖动
    bindDrag(circle, wrapper);
    // hover
    circle.addEventListener("mouseenter", () => { circle.style.transform="scale(1.1)"; circle.style.boxShadow="0 4px 20px rgba(0,0,0,.4)"; });
    circle.addEventListener("mouseleave", () => { circle.style.transform="scale(1)"; circle.style.boxShadow="0 2px 12px rgba(0,0,0,.35)"; });
  }

  function bindDrag(circle, wrapper) {
    let dragging = false, startX, startY, startRight, startTop;
    const onDown = (cx, cy) => {
      dragging = true; circle._dragged = false;
      startX = cx; startY = cy;
      startRight = parseInt(wrapper.style.right) || 8;
      startTop = parseInt(wrapper.style.top) || 120;
      circle.style.transition = "none";
    };
    const onMove = (cx, cy) => {
      if (!dragging) return;
      const dx = startX - cx, dy = cy - startY;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) circle._dragged = true;
      wrapper.style.right = Math.max(4, Math.min(window.innerWidth - 60, startRight + dx)) + "px";
      wrapper.style.top = Math.max(4, Math.min(window.innerHeight - 60, startTop + dy)) + "px";
    };
    const onUp = () => {
      if (!dragging) return;
      dragging = false;
      circle.style.transition = "transform .15s,box-shadow .15s";
      STATE.iconPos = { x: parseInt(wrapper.style.right)||8, y: parseInt(wrapper.style.top)||120 };
    };

    circle.addEventListener("mousedown", e => { onDown(e.clientX, e.clientY); e.preventDefault(); });
    document.addEventListener("mousemove", e => onMove(e.clientX, e.clientY));
    document.addEventListener("mouseup", onUp);
    circle.addEventListener("touchstart", e => { const t=e.touches[0]; onDown(t.clientX, t.clientY); }, {passive:false});
    document.addEventListener("touchmove", e => { const t=e.touches[0]; onMove(t.clientX, t.clientY); }, {passive:false});
    document.addEventListener("touchend", onUp);
  }

  function updateFloatingIcon() {
    const icon = document.getElementById("rc-floating-icon");
    if (!icon) return createFloatingIcon();
    const { color, letter } = getIconStyle();
    const circle = icon.querySelector(".rc-circle");
    if (circle) {
      circle.style.color = color;
      circle.textContent = letter;
      circle.title = [
        STATE.domain || "(无域名)",
        STATE.allFetched
          ? (STATE.matched ? `PROXY · ${STATE.matched.rawLine}` : "DIRECT")
          : "加载中…",
        STATE.latencyMs != null ? `延迟 ${STATE.latencyMs}ms` : "",
      ].filter(Boolean).join("\n");
    }
    const latLabel = icon.querySelector(".rc-latency");
    if (latLabel) {
      latLabel.textContent = STATE.latencyMs != null ? `${STATE.latencyMs}ms` : "—";
    }
  }

  // ======================== 面板 ========================
  function togglePanel() {
    const panel = document.getElementById("rule-checker-panel");
    if (panel) { panel.remove(); return; }
    createPanel();
  }

  function createPanel() {
    const old = document.getElementById("rule-checker-panel"); if (old) old.remove();
    const panel = document.createElement("div");
    panel.id = "rule-checker-panel";
    panel.style.cssText = `position:fixed;top:16px;right:16px;z-index:2147483646;width:280px;max-height:calc(100vh-32px);background:#1e1e2e;color:#cdd6f4;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.45);font-family:-apple-system,"SF Pro Text","Helvetica Neue",sans-serif;font-size:11px;overflow:hidden;display:flex;flex-direction:column;user-select:none;`;
    panel.innerHTML = buildPanelHTML();
    document.body.appendChild(panel);
    bindPanelEvents(panel);
  }

  function buildPanelHTML() {
    const gw = CONFIG.githubWrite;
    const matched = STATE.matched, domain = STATE.domain;
    const suggested = (!matched && STATE.allFetched) ? generateSuggestedRule() : null;

    let statusColor, statusLetter;
    if (!STATE.allFetched) { statusColor = "#f9e2af"; statusLetter = "…"; }
    else if (matched) { statusColor = "#a6e3a1"; statusLetter = "P"; }
    else { statusColor = "#f38ba8"; statusLetter = "D"; }

    const latStr = STATE.latencyMs != null ? `${STATE.latencyMs}ms` : "—";

    return `
      <div style="padding:10px 12px;background:#181825;border-bottom:1px solid #313244;display:flex;justify-content:space-between;align-items:center;">
        <span style="display:flex;align-items:center;gap:6px;">
          <img src="${ICON_PROXY}" style="width:16px;height:16px;">
          <span style="font-weight:700;font-size:12px;color:#cba6f7;">分流规则检测</span>
        </span>
        <div style="display:flex;gap:4px;">
          <button id="rc-refresh" style="background:none;border:1px solid #45475a;color:#a6adc8;cursor:pointer;border-radius:4px;padding:1px 5px;font-size:10px;">🔄</button>
          <button id="rc-close" style="background:none;border:1px solid #45475a;color:#a6adc8;cursor:pointer;border-radius:4px;padding:1px 5px;font-size:10px;">✕</button>
        </div>
      </div>

      <div style="padding:10px 12px;overflow-y:auto;flex:1;">
        <!-- 域名 + 状态 -->
        <div style="margin-bottom:8px;background:#181825;border-radius:8px;padding:8px 10px;border-left:3px solid ${statusColor};">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
            <span style="font-size:10px;color:#6c7086;">主域名</span>
            <span style="font-weight:700;font-size:14px;color:${statusColor};">${statusLetter}</span>
          </div>
          <div style="color:#89b4fa;font-weight:600;font-size:12px;word-break:break-all;">${escapeHTML(domain || "-")}</div>

          <!-- 延迟 -->
          <div style="display:flex;gap:8px;margin-top:4px;font-size:10px;">
            <span style="color:#6c7086;">延迟</span>
            <span style="color:#a6adc8;">${latStr}</span>
            ${STATE.latencyMs != null ? `<span style="color:#585b70;">(TTFB)</span>` : ""}
          </div>
        </div>

        ${matched ? `
        <!-- 命中详情 -->
        <div style="margin-bottom:6px;background:#181825;border-radius:8px;padding:8px 10px;">
          <div style="color:#6c7086;font-size:10px;margin-bottom:3px;">命中规则</div>
          <div style="color:#a6e3a1;word-break:break-all;font-size:11px;">${escapeHTML(matched.rawLine)}</div>
          <div style="font-size:10px;color:#9399b2;margin-top:2px;">${escapeHTML(matched.source)} · ${escapeHTML(matched.type)}</div>
        </div>
        ` : (STATE.allFetched ? `
        <!-- 未命中 → 建议规则 -->
        <div style="margin-bottom:6px;background:#181825;border-radius:8px;padding:8px 10px;">
          <div style="color:#6c7086;font-size:10px;margin-bottom:3px;">建议规则 (${CONFIG.outputMode.toUpperCase()})</div>
          <div style="color:#f9e2af;word-break:break-all;margin-bottom:6px;background:#11111b;padding:5px 7px;border-radius:4px;font-size:11px;">${suggested ? escapeHTML(suggested.line) : "-"}</div>
          <div style="display:flex;gap:6px;">
            <button id="rc-copy" style="background:#45475a;color:#cdd6f4;border:none;border-radius:5px;padding:5px 10px;cursor:pointer;font-size:11px;font-family:inherit;">📋 复制</button>
            <button id="rc-submit" style="background:${gw.token?'#cba6f7':'#313244'};color:${gw.token?'#1e1e2e':'#6c7086'};border:none;border-radius:5px;padding:5px 10px;font-size:11px;font-family:inherit;cursor:${gw.token?'pointer':'not-allowed'};" ${gw.token?'':'disabled'}>🚀 提交</button>
          </div>
        </div>
        ` : '<div style="color:#6c7086;font-size:11px;">规则加载中…</div>')}

        <div style="font-size:10px;color:#585b70;margin-top:4px;">${STATE.rules.length} 条规则</div>
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
      checkDomain();
      measureLatency();
      updateFloatingIcon();
      renderPanelIfOpen();
    });
    panel.querySelector("#rc-close")?.addEventListener("click", () => {
      panel.remove();
    });
    panel.querySelector("#rc-copy")?.addEventListener("click", copyRule);
    panel.querySelector("#rc-submit")?.addEventListener("click", submitRule);
  }

  function renderPanelIfOpen() {
    const panel = document.getElementById("rule-checker-panel");
    if (!panel) return;
    panel.innerHTML = buildPanelHTML();
    bindPanelEvents(panel);
  }

  // ======================== 初始化 ========================
  async function init() {
    log("脚本初始化...");
    STATE.domain = getCleanDomain();
    measureLatency();
    createFloatingIcon();

    await fetchAllRules();
    checkDomain();
    updateFloatingIcon();

    log("初始化完成");
  }

  init();
})();
