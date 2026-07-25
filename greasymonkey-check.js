// ==UserScript==
// @name         代理分流规则检测器
// @namespace    https://github.com/Okayneed/FilterRule
// @version      1.1.0
// @description  自动检测当前域名是否命中 GitHub 托管的代理分流规则，支持 QX / LOON 格式
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
  // 所有敏感信息和可变项集中在此，请按需填写

  const CONFIG = {

    // --- 规则源 ---
    // 每个源包含:
    //   name      : 显示名称
    //   type      : "loon" | "qx"
    //   rawUrl    : GitHub raw 文件地址
    //   enabled   : 是否启用
    // 注意: 为降低负载，默认仅启用 QX 规则集（LOON 规则集与 QX 保持一致，不重复对比）
    ruleSources: [
      {
        name: "GFW-Auto-QX",
        type: "qx",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Auto_gfw.list",
        enabled: true,
      },
      {
        name: "GFW-Auto-LOON",
        type: "loon",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/loon-rule/Auto_gfw.list",
        enabled: false,
      },
      {
        name: "goProxy-Manual-QX",
        type: "qx",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goProxy.list",
        enabled: true,
      },
      {
        name: "goJP-Manual-QX",
        type: "qx",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goJP.list",
        enabled: true,
      },
      {
        name: "goUS-Manual-QX",
        type: "qx",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Manual_goUS.list",
        enabled: true,
      },
      // 在此添加更多规则源...
    ],

    // --- 默认输出模式 ---
    // "loon" → DOMAIN-SUFFIX,example.com
    // "qx"   → host-suffix, example.com
    outputMode: "loon",

    // --- 默认规则类型（生成建议规则时使用） ---
    // "DOMAIN-SUFFIX" | "DOMAIN" | "DOMAIN-KEYWORD"
    defaultRuleType: "DOMAIN-SUFFIX",

    // --- 默认策略名 ---
    defaultPolicy: "Proxy",

    // --- 弹窗时序 ---
    // 页面加载完成后延迟多久弹出面板（毫秒）
    panelShowDelay: 2000,
    // 面板显示多久后自动收起为小图标（毫秒），设为 0 则不自动收起
    panelAutoHideDelay: 5000,

    // --- GitHub 写入功能 ---
    githubWrite: {
      enabled: false,
      owner: "Okayneed",
      repo: "FilterRule",
      branch: "main",
      filePath: "list/Manual_ManualSetting.list",
      token: "",            // <--- 填入你的 GitHub token
    },

    // --- 调试 ---
    debug: false,
  };

  // ======================== 内部状态 ========================
  const STATE = {
    rules: [],
    matched: null,
    currentDomain: "",
    loading: false,
    allFetched: false,
    panelVisible: false,
    iconPos: { x: 0, y: 0 },   // 小图标位置（相对视口右侧/顶部）
    hideTimer: null,
  };

  // ======================== 工具函数 ========================

  function log(...args) {
    if (CONFIG.debug) console.log("[RuleChecker]", ...args);
  }

  function warn(...args) {
    console.warn("[RuleChecker]", ...args);
  }

  function getCleanDomain() {
    let host = window.location.hostname;
    if (host.startsWith("www.")) host = host.slice(4);
    return host;
  }

  // ======================== 规则解析 ========================

  const QX_MAP = {
    "host": "DOMAIN",
    "host-suffix": "DOMAIN-SUFFIX",
    "host-keyword": "DOMAIN-KEYWORD",
    "host-wildcard": "DOMAIN-SUFFIX",
  };

  const LOON_MAP = {
    "DOMAIN": "DOMAIN",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "IP-CIDR": "IP-CIDR",
    "GEOIP": "GEOIP",
    "IP-CIDR6": "IP-CIDR",
  };

  function parseLine(line, sourceType) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!") || trimmed.startsWith("//")) {
      return null;
    }

    const map = sourceType === "qx" ? QX_MAP : LOON_MAP;
    const idx = trimmed.indexOf(",");
    if (idx === -1) return null;

    const rawKey = trimmed.slice(0, idx).trim().toUpperCase();
    const key = sourceType === "qx" ? rawKey.toLowerCase() : rawKey;
    const value = trimmed.slice(idx + 1).trim();

    if (!value) return null;

    const lookupKey = sourceType === "qx" ? key : rawKey;
    const mappedType = map[lookupKey];
    if (!mappedType) return null;

    let finalValue = value;
    if (lookupKey === "host-wildcard" && finalValue.startsWith(".")) {
      finalValue = finalValue.slice(1);
    }

    return { type: mappedType, value: finalValue };
  }

  function parseRules(text, sourceType) {
    const lines = text.split(/\r?\n/);
    const rules = [];
    for (const line of lines) {
      const parsed = parseLine(line, sourceType);
      if (parsed) rules.push(parsed);
    }
    return rules;
  }

  // ======================== 规则匹配 ========================

  function matchRule(domain, rule) {
    const d = domain.toLowerCase();
    const v = rule.value.toLowerCase();

    switch (rule.type) {
      case "DOMAIN":
        return d === v;
      case "DOMAIN-SUFFIX":
        return d === v || d.endsWith("." + v);
      case "DOMAIN-KEYWORD":
        return d.includes(v);
      default:
        return false;
    }
  }

  // ======================== 规则拉取 ========================

  function fetchRuleSource(source) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: "GET",
        url: source.rawUrl,
        timeout: 15000,
        onload: function (resp) {
          if (resp.status >= 200 && resp.status < 300) {
            log(`[${source.name}] 拉取成功, ${resp.responseText.length} 字节`);
            resolve(resp.responseText);
          } else {
            warn(`[${source.name}] HTTP ${resp.status}`);
            reject(new Error(`HTTP ${resp.status}`));
          }
        },
        onerror: function (err) {
          warn(`[${source.name}] 网络错误:`, err);
          reject(err);
        },
        ontimeout: function () {
          warn(`[${source.name}] 请求超时`);
          reject(new Error("timeout"));
        },
      });
    });
  }

  async function fetchAllRules() {
    if (STATE.loading) return;
    STATE.loading = true;
    STATE.rules = [];

    const enabledSources = CONFIG.ruleSources.filter((s) => s.enabled);
    log(`开始拉取 ${enabledSources.length} 个规则源...`);

    const promises = enabledSources.map(async (source) => {
      try {
        const text = await fetchRuleSource(source);
        const parsed = parseRules(text, source.type);
        parsed.forEach((r) => {
          r.source = source.name;
          r.rawLine = `${r.type},${r.value}`;
        });
        STATE.rules.push(...parsed);
        log(`[${source.name}] 解析到 ${parsed.length} 条规则`);
      } catch (err) {
        warn(`[${source.name}] 拉取失败，跳过: ${err.message}`);
      }
    });

    await Promise.allSettled(promises);
    STATE.allFetched = true;
    STATE.loading = false;
    log(`规则加载完成，共 ${STATE.rules.length} 条`);
  }

  // ======================== 主检测逻辑 ========================

  function checkDomain() {
    const domain = getCleanDomain();
    STATE.currentDomain = domain;
    STATE.matched = null;

    if (!domain) return;

    for (const rule of STATE.rules) {
      if (matchRule(domain, rule)) {
        STATE.matched = rule;
        break;
      }
    }
  }

  // ======================== 建议规则生成 ========================

  function generateSuggestedRule() {
    const domain = STATE.currentDomain;
    if (!domain) return null;

    const mode = CONFIG.outputMode;
    const ruleType = CONFIG.defaultRuleType;

    let line;
    if (mode === "loon") {
      line = `${ruleType},${domain}`;
    } else {
      const qxType = ruleType
        .replace("DOMAIN", "host")
        .replace("-SUFFIX", "-suffix")
        .replace("-KEYWORD", "-keyword");
      line = `${qxType}, ${domain}`;
    }

    return { line, policy: CONFIG.defaultPolicy };
  }

  // ======================== 复制到剪贴板 ========================

  function copySuggestedRule() {
    const suggested = generateSuggestedRule();
    if (!suggested) return;
    GM_setClipboard(suggested.line, "text");
    showToast("已复制: " + suggested.line);
    log("复制建议规则:", suggested.line);
  }

  // ======================== GitHub 写入（预留） ========================

  const GitHubWriter = {
    async getFileSha() {
      const gw = CONFIG.githubWrite;
      const url = `https://api.github.com/repos/${gw.owner}/${gw.repo}/contents/${gw.filePath}?ref=${gw.branch}`;
      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: "GET",
          url: url,
          headers: {
            Authorization: `token ${gw.token}`,
            Accept: "application/vnd.github.v3+json",
          },
          onload: function (resp) {
            if (resp.status === 200) {
              const data = JSON.parse(resp.responseText);
              resolve({
                sha: data.sha,
                content: atob(data.content.replace(/\n/g, "")),
              });
            } else {
              reject(new Error(`获取文件失败: HTTP ${resp.status}`));
            }
          },
          onerror: reject,
        });
      });
    },

    async appendRule(ruleLine) {
      const gw = CONFIG.githubWrite;
      if (!gw.enabled || !gw.token) {
        showToast("GitHub 写入未启用或无 token", "error");
        return;
      }

      try {
        const { sha, content } = await this.getFileSha();
        if (content.includes(ruleLine)) {
          showToast("规则已存在，跳过添加", "warn");
          return;
        }

        const newContent = content.trimEnd() + "\n" + ruleLine + "\n";
        const encoded = btoa(unescape(encodeURIComponent(newContent)));
        const url = `https://api.github.com/repos/${gw.owner}/${gw.repo}/contents/${gw.filePath}`;

        await new Promise((resolve, reject) => {
          GM_xmlhttpRequest({
            method: "PUT",
            url: url,
            headers: {
              Authorization: `token ${gw.token}`,
              Accept: "application/vnd.github.v3+json",
              "Content-Type": "application/json",
            },
            data: JSON.stringify({
              message: `[auto] add rule: ${ruleLine}`,
              content: encoded,
              sha: sha,
              branch: gw.branch,
            }),
            onload: function (resp) {
              if (resp.status === 200 || resp.status === 201) {
                resolve(JSON.parse(resp.responseText));
              } else {
                reject(new Error(`提交失败: HTTP ${resp.status} - ${resp.responseText}`));
              }
            },
            onerror: reject,
          });
        });

        showToast("规则已提交到 GitHub: " + ruleLine);
        log("GitHub 写入成功:", ruleLine);

        STATE.rules.push({
          type: CONFIG.defaultRuleType,
          value: STATE.currentDomain,
          source: `${gw.owner}/${gw.repo}`,
          rawLine: ruleLine,
        });
        STATE.matched = STATE.rules[STATE.rules.length - 1];
        renderPanel();
      } catch (err) {
        showToast("GitHub 写入失败: " + err.message, "error");
        warn("GitHub 写入失败:", err);
      }
    },
  };

  // ======================== Toast 提示 ========================

  function showToast(msg, type) {
    const old = document.getElementById("rc-toast");
    if (old) old.remove();

    const toast = document.createElement("div");
    toast.id = "rc-toast";
    const bg = type === "error" ? "#e74c3c" : type === "warn" ? "#f39c12" : "#27ae60";
    toast.style.cssText = `
      position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
      background: ${bg}; color: #fff; padding: 10px 20px; border-radius: 8px;
      font-size: 13px; z-index: 2147483647; box-shadow: 0 4px 16px rgba(0,0,0,.2);
      pointer-events: none; transition: opacity .3s; opacity: 1;
    `;
    toast.textContent = msg;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }

  // ======================== 浮窗 UI（收起 / 展开） ========================

  /**
   * 收起面板 → 显示可拖动小图标
   */
  function collapseToIcon() {
    const panel = document.getElementById("rule-checker-panel");
    if (panel) panel.remove();

    STATE.panelVisible = false;
    clearTimeout(STATE.hideTimer);
    createFloatingIcon();
  }

  /**
   * 点击小图标 → 展开面板
   */
  function expandPanel() {
    const icon = document.getElementById("rc-floating-icon");
    if (icon) {
      // 保存 icon 位置，面板展开在附近
      const rect = icon.getBoundingClientRect();
      STATE.iconPos = { x: window.innerWidth - rect.right, y: rect.top };
      icon.remove();
    }

    createPanel();
    STATE.panelVisible = true;

    // 重新启动自动收起计时
    if (CONFIG.panelAutoHideDelay > 0) {
      STATE.hideTimer = setTimeout(collapseToIcon, CONFIG.panelAutoHideDelay);
    }
  }

  // ======================== 可拖动小图标 ========================

  function createFloatingIcon() {
    const old = document.getElementById("rc-floating-icon");
    if (old) old.remove();

    // 命中 / 未命中 状态颜色
    const matched = STATE.matched;
    const allFetched = STATE.allFetched;
    let bgColor, emoji;
    if (!allFetched) {
      bgColor = "#f9e2af";
      emoji = "⏳";
    } else if (matched) {
      bgColor = "#a6e3a1";
      emoji = "✅";
    } else {
      bgColor = "#f38ba8";
      emoji = "❌";
    }

    const icon = document.createElement("div");
    icon.id = "rc-floating-icon";
    icon.title = [
      STATE.currentDomain || "(无域名)",
      allFetched ? (matched ? "已命中 · 点击查看详情" : "未命中 · 点击查看详情") : "加载中...",
    ].join("\n");

    // 默认位置：右上角偏中
    const x = STATE.iconPos.x || 8;
    const y = STATE.iconPos.y || 120;

    icon.style.cssText = `
      position: fixed; z-index: 2147483645;
      top: ${y}px; right: ${x}px;
      width: 36px; height: 36px; border-radius: 50%;
      background: ${bgColor}; color: #1e1e2e;
      display: flex; align-items: center; justify-content: center;
      font-size: 16px; cursor: pointer;
      box-shadow: 0 2px 12px rgba(0,0,0,.3);
      transition: transform .15s, box-shadow .15s;
      user-select: none;
    `;

    // 点击展开面板
    icon.addEventListener("click", function (e) {
      // 区分拖拽和点击：移动距离 < 3px 视为点击
      if (icon._dragged) return;
      expandPanel();
    });

    // --- 拖动逻辑 ---
    let dragging = false;
    let startX, startY, startRight, startTop;

    icon.addEventListener("mousedown", function (e) {
      dragging = true;
      icon._dragged = false;
      startX = e.clientX;
      startY = e.clientY;
      startRight = parseInt(icon.style.right) || 8;
      startTop = parseInt(icon.style.top) || 120;
      icon.style.transition = "none";
      e.preventDefault();
    });

    document.addEventListener("mousemove", function (e) {
      if (!dragging) return;
      const dx = startX - e.clientX;
      const dy = e.clientY - startY;
      const newRight = startRight + dx;
      const newTop = startTop + dy;

      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
        icon._dragged = true;
      }

      // 限制在视口内
      const clampedTop = Math.max(4, Math.min(window.innerHeight - 44, newTop));
      const clampedRight = Math.max(4, Math.min(window.innerWidth - 44, newRight));

      icon.style.right = clampedRight + "px";
      icon.style.top = clampedTop + "px";
    });

    document.addEventListener("mouseup", function () {
      if (dragging) {
        dragging = false;
        icon.style.transition = "transform .15s, box-shadow .15s";
        // 保存位置
        STATE.iconPos = {
          x: parseInt(icon.style.right) || 8,
          y: parseInt(icon.style.top) || 120,
        };
      }
    });

    // 触摸支持
    icon.addEventListener("touchstart", function (e) {
      dragging = true;
      icon._dragged = false;
      const t = e.touches[0];
      startX = t.clientX;
      startY = t.clientY;
      startRight = parseInt(icon.style.right) || 8;
      startTop = parseInt(icon.style.top) || 120;
      icon.style.transition = "none";
    }, { passive: false });

    document.addEventListener("touchmove", function (e) {
      if (!dragging) return;
      const t = e.touches[0];
      const dx = startX - t.clientX;
      const dy = t.clientY - startY;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
        icon._dragged = true;
      }
      icon.style.right = Math.max(4, Math.min(window.innerWidth - 44, startRight + dx)) + "px";
      icon.style.top = Math.max(4, Math.min(window.innerHeight - 44, startTop + dy)) + "px";
    }, { passive: false });

    document.addEventListener("touchend", function () {
      if (dragging) {
        dragging = false;
        icon.style.transition = "transform .15s, box-shadow .15s";
        STATE.iconPos = {
          x: parseInt(icon.style.right) || 8,
          y: parseInt(icon.style.top) || 120,
        };
      }
    });

    // hover 效果
    icon.addEventListener("mouseenter", function () {
      icon.style.transform = "scale(1.1)";
      icon.style.boxShadow = "0 4px 20px rgba(0,0,0,.4)";
    });
    icon.addEventListener("mouseleave", function () {
      icon.style.transform = "scale(1)";
      icon.style.boxShadow = "0 2px 12px rgba(0,0,0,.3)";
    });

    document.body.appendChild(icon);
  }

  // ======================== 展开面板 ========================

  function createPanel() {
    const old = document.getElementById("rule-checker-panel");
    if (old) old.remove();

    const panel = document.createElement("div");
    panel.id = "rule-checker-panel";
    panel.style.cssText = `
      position: fixed; top: 16px; right: 16px; z-index: 2147483646;
      width: 270px; max-height: calc(100vh - 32px);
      background: #1e1e2e; color: #cdd6f4; border-radius: 10px;
      box-shadow: 0 6px 24px rgba(0,0,0,.45); font-family: -apple-system, "SF Pro Text", "Helvetica Neue", sans-serif;
      font-size: 11px; overflow: hidden; display: flex; flex-direction: column;
      user-select: none;
    `;
    panel.innerHTML = buildPanelHTML();
    document.body.appendChild(panel);
    bindPanelEvents(panel);
  }

  function buildPanelHTML() {
    const matched = STATE.matched;
    const domain = STATE.currentDomain;
    const suggested = !matched ? generateSuggestedRule() : null;
    const gw = CONFIG.githubWrite;

    let statusText, hitColor;
    if (!STATE.allFetched) {
      statusText = "⏳ 规则加载中...";
      hitColor = "#f9e2af";
    } else if (matched) {
      statusText = "✅ 已命中";
      hitColor = "#a6e3a1";
    } else {
      statusText = "❌ 未命中";
      hitColor = "#f38ba8";
    }

    return `
      <div style="
        padding: 10px 12px; background: #181825; border-bottom: 1px solid #313244;
        display: flex; justify-content: space-between; align-items: center; gap: 8px;
      ">
        <span style="font-weight: 700; font-size: 12px; color: #cba6f7;">分流规则检测</span>
        <div style="display: flex; gap: 4px;">
          <button id="rc-refresh" title="刷新规则" style="
            background: none; border: 1px solid #45475a; color: #a6adc8; cursor: pointer;
            border-radius: 4px; padding: 1px 5px; font-size: 10px; line-height: 1.5;
          ">🔄</button>
          <button id="rc-minimize" title="收起为小图标" style="
            background: none; border: 1px solid #45475a; color: #a6adc8; cursor: pointer;
            border-radius: 4px; padding: 1px 5px; font-size: 10px; line-height: 1.5;
          ">—</button>
        </div>
      </div>

      <div style="padding: 10px 12px; overflow-y: auto; flex: 1;">
        <div style="margin-bottom: 8px;">
          <span style="color: #6c7086; font-size: 10px;">当前域名</span>
          <div style="color: #89b4fa; font-weight: 600; font-size: 12px; word-break: break-all;">
            ${domain || "-"}
          </div>
        </div>

        <div style="margin-bottom: 8px;">
          <span style="color: #6c7086; font-size: 10px;">检测状态</span>
          <div style="color: ${hitColor}; font-weight: 600; font-size: 12px;">
            ${statusText}
          </div>
        </div>

        ${matched ? `
        <div style="margin-bottom: 6px; background: #181825; border-radius: 8px; padding: 8px 10px;">
          <div style="color: #6c7086; font-size: 10px; margin-bottom: 3px;">命中规则</div>
          <div style="color: #a6e3a1; word-break: break-all; margin-bottom: 4px; font-size: 11px;">
            ${escapeHTML(matched.rawLine)}
          </div>
          <div style="font-size: 10px; color: #9399b2;">
            <span>${escapeHTML(matched.source)}</span>
            <span style="margin-left: 8px;">${escapeHTML(matched.type)}</span>
          </div>
          <div style="font-size: 10px; color: #585b70; margin-top: 2px;">
            策略: ${escapeHTML(CONFIG.defaultPolicy)}
          </div>
        </div>
        ` : (STATE.allFetched ? `
        <div style="margin-bottom: 6px; background: #181825; border-radius: 8px; padding: 8px 10px;">
          <div style="color: #6c7086; font-size: 10px; margin-bottom: 3px;">建议规则 (${CONFIG.outputMode.toUpperCase()})</div>
          <div style="
            color: #f9e2af; word-break: break-all; margin-bottom: 6px;
            background: #11111b; padding: 5px 7px; border-radius: 4px; font-size: 11px;
          ">${suggested ? escapeHTML(suggested.line) : "-"}</div>
          <div style="display: flex; gap: 6px;">
            <button id="rc-copy" style="
              background: #45475a; color: #cdd6f4; border: none; border-radius: 5px;
              padding: 5px 10px; cursor: pointer; font-size: 11px; font-family: inherit;
            ">📋 复制</button>
            <button id="rc-submit" title="提交到 GitHub（需配置 token）" style="
              background: #313244; color: #6c7086; border: none; border-radius: 5px;
              padding: 5px 10px; font-size: 11px; font-family: inherit;
              ${gw.enabled && gw.token ? 'cursor: pointer; color: #cba6f7;' : 'cursor: not-allowed;'}
            " ${gw.enabled && gw.token ? '' : 'disabled'}>🚀 提交</button>
          </div>
        </div>
        ` : '')}

        <div style="font-size: 10px; color: #585b70; margin-top: 2px;">
          ${STATE.rules.length} 条规则${STATE.loading ? ' · 加载中...' : ''}
        </div>
      </div>
    `;
  }

  function escapeHTML(str) {
    const el = document.createElement("span");
    el.textContent = str;
    return el.innerHTML;
  }

  function bindPanelEvents(panel) {
    const btnRefresh = panel.querySelector("#rc-refresh");
    const btnCopy = panel.querySelector("#rc-copy");
    const btnSubmit = panel.querySelector("#rc-submit");
    const btnMinimize = panel.querySelector("#rc-minimize");

    if (btnRefresh) {
      btnRefresh.addEventListener("click", async () => {
        btnRefresh.textContent = "⏳";
        btnRefresh.disabled = true;
        STATE.allFetched = false;
        await fetchAllRules();
        checkDomain();
        renderPanel();
      });
    }

    if (btnCopy) {
      btnCopy.addEventListener("click", copySuggestedRule);
    }

    if (btnSubmit) {
      btnSubmit.addEventListener("click", () => {
        const suggested = generateSuggestedRule();
        if (suggested) GitHubWriter.appendRule(suggested.line);
      });
    }

    if (btnMinimize) {
      btnMinimize.addEventListener("click", collapseToIcon);
    }
  }

  function renderPanel() {
    const panel = document.getElementById("rule-checker-panel");
    if (!panel) return;
    panel.innerHTML = buildPanelHTML();
    bindPanelEvents(panel);
  }

  // ======================== 初始化 ========================

  async function init() {
    log("脚本初始化...");
    STATE.currentDomain = getCleanDomain();

    // 先拉取规则（后台进行）
    const fetchPromise = fetchAllRules();

    // 等待配置的延迟后再显示面板
    await new Promise((r) => setTimeout(r, CONFIG.panelShowDelay));
    await fetchPromise;

    checkDomain();
    createPanel();
    STATE.panelVisible = true;

    // 自动收起计时
    if (CONFIG.panelAutoHideDelay > 0) {
      STATE.hideTimer = setTimeout(collapseToIcon, CONFIG.panelAutoHideDelay);
    }

    log("初始化完成");
  }

  init();

})();
