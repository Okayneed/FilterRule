// ==UserScript==
// @name         代理分流规则检测器
// @namespace    https://github.com/Okayneed/FilterRule
// @version      1.0.0
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
    //   name      : 显示名称（任意字符串）
    //   type      : "loon" | "qx"（源格式）
    //   rawUrl    : GitHub raw 文件地址
    //   enabled   : 是否启用拉取
    ruleSources: [
      {
        name: "GFW-Auto-LOON",
        type: "loon",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/loon-rule/Auto_gfw.list",
        enabled: true,
      },
      {
        name: "GFW-Auto-QX",
        type: "qx",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/list/Auto_gfw.list",
        enabled: false,
      },
      {
        name: "goProxy-Manual-LOON",
        type: "loon",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/loon-rule/Manual_goProxy.list",
        enabled: true,
      },
      {
        name: "goJP-Manual-LOON",
        type: "loon",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/loon-rule/Manual_goJP.list",
        enabled: true,
      },
      {
        name: "goUS-Manual-LOON",
        type: "loon",
        rawUrl: "https://raw.githubusercontent.com/Okayneed/FilterRule/main/loon-rule/Manual_goUS.list",
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

    // --- GitHub 写入功能 ---
    githubWrite: {
      enabled: false,       // 总开关，默认关闭
      owner: "Okayneed",    // 仓库所有者
      repo: "FilterRule",   // 仓库名
      branch: "main",       // 分支
      // 写入的文件路径（相对于仓库根目录）
      filePath: "loon-rule/Manual_ManualSetting.list",
      // GitHub Personal Access Token（需 repo 权限）
      // ⚠️ 请勿公开分享含 token 的脚本
      token: "",            // <--- 填入你的 GitHub token
    },

    // --- 浮窗样式 ---
    panel: {
      position: "top-right",  // 固定右上角
      width: "360px",
    },

    // --- 调试 ---
    debug: false,
  };

  // ======================== 内部状态 ========================
  const STATE = {
    rules: [],           // [{type, value, source, rawLine}]
    matched: null,       // 命中结果
    currentDomain: "",
    loading: false,
    allFetched: false,
  };

  // ======================== 工具函数 ========================

  function log(...args) {
    if (CONFIG.debug) console.log("[RuleChecker]", ...args);
  }

  function warn(...args) {
    console.warn("[RuleChecker]", ...args);
  }

  /** 获取当前页面的纯净域名（去除 www 前缀） */
  function getCleanDomain() {
    let host = window.location.hostname;
    if (host.startsWith("www.")) host = host.slice(4);
    return host;
  }

  // ======================== 规则解析 ========================

  /**
   * 将 QX / LOON 格式统一映射为内部结构
   * 内部结构: { type: "DOMAIN"|"DOMAIN-SUFFIX"|"DOMAIN-KEYWORD"|"IP-CIDR"|"GEOIP", value: string }
   *
   * QX 格式映射:
   *   host, domain       → DOMAIN
   *   host-suffix, domain → DOMAIN-SUFFIX
   *   host-keyword, kw   → DOMAIN-KEYWORD
   *   host-wildcard, .example.com → DOMAIN-SUFFIX
   *
   * LOON 格式映射:
   *   DOMAIN,domain          → DOMAIN
   *   DOMAIN-SUFFIX,domain   → DOMAIN-SUFFIX
   *   DOMAIN-KEYWORD,kw      → DOMAIN-KEYWORD
   *   HOST,domain            → DOMAIN
   *   HOST-SUFFIX,domain     → DOMAIN-SUFFIX
   *   HOST-KEYWORD,kw        → DOMAIN-KEYWORD
   *   IP-CIDR,ip/mask        → IP-CIDR (预留)
   *   GEOIP,code             → GEOIP (预留)
   */

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
    // 跳过空行和注释
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!") || trimmed.startsWith("//")) {
      return null;
    }

    const map = sourceType === "qx" ? QX_MAP : LOON_MAP;
    // 支持 "," 或 ", " 分隔
    const idx = trimmed.indexOf(",");
    if (idx === -1) return null;

    const rawKey = trimmed.slice(0, idx).trim().toUpperCase();
    // 对于 QX 格式保持小写匹配
    const key = sourceType === "qx" ? rawKey.toLowerCase() : rawKey;
    const value = trimmed.slice(idx + 1).trim();

    if (!value) return null;

    // 映射 key
    const lookupKey = sourceType === "qx" ? key : rawKey;
    const mappedType = map[lookupKey];

    if (!mappedType) return null;

    // QX host-wildcard 特殊处理: .example.com → 同上
    let finalValue = value;
    if (lookupKey === "host-wildcard" && finalValue.startsWith(".")) {
      finalValue = finalValue.slice(1);
    }

    // IP / GEO 类型预留解析但不强制参与域名匹配
    return {
      type: mappedType,
      value: finalValue,
    };
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

  /**
   * 匹配逻辑：
   *   DOMAIN          → 精确匹配（忽略大小写）
   *   DOMAIN-SUFFIX   → 后缀匹配：domain === ruleValue 或 domain.endsWith("." + ruleValue)
   *   DOMAIN-KEYWORD  → 关键词包含
   */
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
        // 标记来源
        parsed.forEach((r) => {
          r.source = source.name;
          r.rawLine = `${r.type},${r.value}`;
        });
        STATE.rules.push(...parsed);
        log(`[${source.name}] 解析到 ${parsed.length} 条规则`);
      } catch (err) {
        // 拉取失败不中断
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
        break; // 取第一个命中
      }
    }
  }

  // ======================== 建议规则生成 ========================

  function generateSuggestedRule() {
    const domain = STATE.currentDomain;
    if (!domain) return null;

    const mode = CONFIG.outputMode;
    const ruleType = CONFIG.defaultRuleType;
    const policy = CONFIG.defaultPolicy;

    let line;
    if (mode === "loon") {
      line = `${ruleType},${domain}`;
    } else {
      // QX 格式
      const qxType = ruleType
        .replace("DOMAIN", "host")
        .replace("-SUFFIX", "-suffix")
        .replace("-KEYWORD", "-keyword");
      line = `${qxType}, ${domain}`;
    }

    return {
      line: line,
      policy: policy,
    };
  }

  // ======================== 复制到剪贴板 ========================

  function copySuggestedRule() {
    const suggested = generateSuggestedRule();
    if (!suggested) return;

    const text = suggested.line;
    GM_setClipboard(text, "text");
    showToast("已复制: " + text);
    log("复制建议规则:", text);
  }

  // ======================== GitHub 写入（预留） ========================

  /**
   * GitHub 写入功能 - 预留函数
   * 流程: 读取文件 → 获取 sha → 追加规则 → commit
   * 通过 CONFIG.githubWrite.enabled 控制开关
   */
  const GitHubWriter = {
    /** 获取文件当前内容和 SHA */
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
                content: atob(data.content.replace(/\n/g, "")), // Base64 解码
              });
            } else {
              reject(new Error(`获取文件失败: HTTP ${resp.status}`));
            }
          },
          onerror: reject,
        });
      });
    },

    /** 追加规则并提交 */
    async appendRule(ruleLine) {
      const gw = CONFIG.githubWrite;
      if (!gw.enabled || !gw.token) {
        showToast("GitHub 写入未启用或无 token", "error");
        return;
      }

      try {
        // 1. 读取文件
        const { sha, content } = await this.getFileSha();

        // 2. 避免重复添加
        if (content.includes(ruleLine)) {
          showToast("规则已存在，跳过添加", "warn");
          log("规则已存在:", ruleLine);
          return;
        }

        // 3. 追加规则
        const newContent = content.trimEnd() + "\n" + ruleLine + "\n";
        const encoded = btoa(unescape(encodeURIComponent(newContent)));

        const url = `https://api.github.com/repos/${gw.owner}/${gw.repo}/contents/${gw.filePath}`;
        const commitMsg = `[auto] add rule: ${ruleLine}`;

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
              message: commitMsg,
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

        // 刷新本地规则缓存（新规则直接加入）
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
    // 移除旧 toast
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

  // ======================== 浮窗 UI ========================

  function createPanel() {
    // 移除旧面板
    const old = document.getElementById("rule-checker-panel");
    if (old) old.remove();

    const panel = document.createElement("div");
    panel.id = "rule-checker-panel";
    panel.style.cssText = `
      position: fixed; top: 16px; right: 16px; z-index: 2147483646;
      width: ${CONFIG.panel.width}; max-height: calc(100vh - 32px);
      background: #1e1e2e; color: #cdd6f4; border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,.4); font-family: "SF Mono", Menlo, Consolas, monospace;
      font-size: 12px; overflow: hidden; display: flex; flex-direction: column;
      transition: opacity .3s; user-select: none;
    `;
    panel.innerHTML = buildPanelHTML();
    document.body.appendChild(panel);

    // 事件绑定
    bindPanelEvents(panel);
  }

  function buildPanelHTML() {
    const matched = STATE.matched;
    const domain = STATE.currentDomain;
    const suggested = !matched ? generateSuggestedRule() : null;
    const gw = CONFIG.githubWrite;

    let statusClass, statusText, hitColor;
    if (!STATE.allFetched) {
      statusClass = "loading";
      statusText = "⏳ 规则加载中...";
      hitColor = "#f9e2af";
    } else if (matched) {
      statusClass = "hit";
      statusText = "✅ 已命中";
      hitColor = "#a6e3a1";
    } else {
      statusClass = "miss";
      statusText = "❌ 未命中";
      hitColor = "#f38ba8";
    }

    return `
      <div class="rc-header" style="
        padding: 12px 14px; background: #181825; border-bottom: 1px solid #313244;
        display: flex; justify-content: space-between; align-items: center;
      ">
        <span style="font-weight: 700; font-size: 13px; color: #cba6f7;">🔍 分流规则检测</span>
        <button id="rc-refresh" title="刷新规则" style="
          background: none; border: 1px solid #45475a; color: #a6adc8; cursor: pointer;
          border-radius: 6px; padding: 2px 6px; font-size: 11px;
        ">🔄 刷新</button>
      </div>

      <div class="rc-body" style="padding: 12px 14px; overflow-y: auto; flex: 1;">
        <!-- 当前域名 -->
        <div style="margin-bottom: 10px;">
          <span style="color: #6c7086; font-size: 10px;">当前域名</span>
          <div style="color: #89b4fa; font-weight: 600; font-size: 14px; word-break: break-all;">
            ${domain || "-"}
          </div>
        </div>

        <!-- 状态 -->
        <div style="margin-bottom: 10px;">
          <span style="color: #6c7086; font-size: 10px;">检测状态</span>
          <div style="color: ${hitColor}; font-weight: 600; font-size: 13px;">
            ${statusText}
          </div>
        </div>

        ${matched ? `
        <!-- 命中详情 -->
        <div class="rc-section" style="margin-bottom: 8px; background: #181825; border-radius: 8px; padding: 10px;">
          <div style="color: #6c7086; font-size: 10px; margin-bottom: 4px;">命中规则</div>
          <div style="color: #a6e3a1; word-break: break-all; margin-bottom: 6px;">
            ${escapeHTML(matched.rawLine)}
          </div>
          <div style="display: flex; gap: 12px; font-size: 10px;">
            <span><span style="color: #6c7086;">来源:</span> ${escapeHTML(matched.source)}</span>
            <span><span style="color: #6c7086;">类型:</span> ${escapeHTML(matched.type)}</span>
          </div>
          <div style="font-size: 10px; margin-top: 4px;">
            <span style="color: #6c7086;">策略:</span> ${escapeHTML(CONFIG.defaultPolicy)}
          </div>
        </div>
        ` : (STATE.allFetched ? `
        <!-- 建议规则 -->
        <div class="rc-section" style="margin-bottom: 8px; background: #181825; border-radius: 8px; padding: 10px;">
          <div style="color: #6c7086; font-size: 10px; margin-bottom: 4px;">建议规则（${CONFIG.outputMode.toUpperCase()} 格式）</div>
          <div class="rc-suggested" style="
            color: #f9e2af; word-break: break-all; margin-bottom: 8px;
            background: #11111b; padding: 6px 8px; border-radius: 4px;
          ">${suggested ? escapeHTML(suggested.line) : "-"}</div>
          <div style="display: flex; gap: 8px;">
            <button id="rc-copy" style="
              background: #45475a; color: #cdd6f4; border: none; border-radius: 6px;
              padding: 6px 12px; cursor: pointer; font-size: 11px; font-family: inherit;
            ">📋 复制建议规则</button>
            <button id="rc-submit" title="提交规则到 GitHub（需在配置中启用并填写 token）" style="
              background: #313244; color: #6c7086; border: none; border-radius: 6px;
              padding: 6px 12px; font-size: 11px; font-family: inherit;
              ${gw.enabled && gw.token ? 'cursor: pointer; color: #cba6f7;' : 'cursor: not-allowed;'}
            " ${gw.enabled && gw.token ? '' : 'disabled'}>🚀 提交到 GitHub</button>
          </div>
        </div>
        ` : '')}

        <!-- 规则来源统计 -->
        <div style="font-size: 10px; color: #585b70; margin-top: 4px;">
          已加载 ${STATE.rules.length} 条规则
          ${STATE.loading ? ' · 加载中...' : ''}
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

    if (btnRefresh) {
      btnRefresh.addEventListener("click", async () => {
        btnRefresh.textContent = "⏳ 刷新中...";
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
        if (suggested) {
          GitHubWriter.appendRule(suggested.line);
        }
      });
    }
  }

  function renderPanel() {
    const panel = document.getElementById("rule-checker-panel");
    if (panel) {
      panel.innerHTML = buildPanelHTML();
      bindPanelEvents(panel);
    }
  }

  // ======================== 初始化 ========================

  async function init() {
    log("脚本初始化...");
    createPanel();
    STATE.currentDomain = getCleanDomain();

    // 异步拉取规则，不阻塞页面
    await fetchAllRules();
    checkDomain();
    renderPanel();

    log("初始化完成");
  }

  // 启动
  init();

})();
