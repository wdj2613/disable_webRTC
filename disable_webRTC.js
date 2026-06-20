// ==UserScript==
// @name         禁止WebRTC
// @version      2.9.0
// @description  仅对 GFWList + 自定义域名启用 WebRTC 防护（强制 relay + SDP 清理，杜绝真实 IP 泄露），其余站点正常放行
// @match        *://*/*
// @grant        unsafeWindow
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @run-at       document-start
// @license      MIT
// @namespace    https://www.tampermonkey.net/
// ==/UserScript==
 
'use strict';
 
/* ══════════════════════════════════════════════════════════════
   配置区
   ══════════════════════════════════════════════════════════════ */
const CONFIG = {
  GFWLIST_URL:    'https://raw.githubusercontent.com/boy86001/SmartProxy-Tools/main/gfwlist.txt',
 
  CACHE_KEY:      'gfwlist_domains_v2',
  CACHE_TIME_KEY: 'gfwlist_fetch_time_v2',
  CUSTOM_KEY:     'gfwlist_custom_domains_v2',
  TTL_KEY:        'gfwlist_ttl_hours_v2',
 
  DEFAULT_TTL_HOURS: 12,
 
  FORCE_ALLOW: [
    // 'https://meet.jit.si',
    // 'https://whereby.com',
  ],
};
 
let debugMode = GM_getValue('debug_mode_v2', false);
const log = (...args) => { if (debugMode) console.log('[WebRTC-GFW]', ...args); };
 
let gfwCacheDomains = null;
 
/* ══════════════════════════════════════════════════════════════
   工具函数
   ══════════════════════════════════════════════════════════════ */
function getCacheTTL() {
  const hours = Number(GM_getValue(CONFIG.TTL_KEY, CONFIG.DEFAULT_TTL_HOURS));
  return (isFinite(hours) && hours >= 1 ? hours : CONFIG.DEFAULT_TTL_HOURS) * 3600000;
}
 
/* ══════════════════════════════════════════════════════════════
   核心 Hook（普通函数，既可直接调用、也可序列化后注入）
   ── 两条互补的应用路径，专为兼容 Via 等移动端浏览器设计：
      1) 直接以页面 window 调用：CSP 友好，页内引擎（Via）/ Tampermonkey
         的 unsafeWindow 都能命中，不受 script-src 限制。
      2) 序列化注入 <script>：隔离环境引擎的补充路径，若被 CSP 拦截则
         静默失效，由路径 1 兜底。
   全程 ES5 语法 + try/catch 包裹，兼容老旧 WebView。
   ══════════════════════════════════════════════════════════════ */
function rtcHook(win) {
  "use strict";
  try {
    var OrigPC = win.RTCPeerConnection || win.webkitRTCPeerConnection || win.mozRTCPeerConnection;
    if (!OrigPC) return;
    if (win.__webrtcGfwHooked) return;   // 幂等：同一 realm 只 hook 一次
    win.__webrtcGfwHooked = true;

    var RTCSD = win.RTCSessionDescription;

    function stripIPsFromSDP(sdp) {
      if (!sdp) return sdp;
      return sdp.split("\n").filter(function(line) {
        if (line.indexOf("a=candidate:") !== -1) return false;   // 去掉 ICE candidate 行
        if (/^c=IN/.test(line)) return false;                    // 去掉连接地址行
        return true;
      }).join("\n");
    }
    // 仅放行 relay candidate 及 null/空（含 end-of-candidates）
    function isRelay(c) {
      if (!c || !c.candidate) return true;
      return c.candidate.indexOf(" relay ") !== -1;
    }
    function wrapDesc(desc) {
      if (desc && desc.sdp) {
        var clean = stripIPsFromSDP(desc.sdp);
        if (RTCSD) { try { return new RTCSD({ type: desc.type, sdp: clean }); } catch(e) {} }
        return { type: desc.type, sdp: clean };
      }
      return desc;
    }

    function HookedPC(config, constraints) {
      if (!config) config = {};
      config.iceTransportPolicy = "relay";          // 强制 relay：无 TURN 即无候选，真实 IP 不外泄
      var pc = new OrigPC(config, constraints);

      // localDescription 全系列 getter 去 IP
      ["localDescription", "currentLocalDescription", "pendingLocalDescription"].forEach(function(prop) {
        try {
          var d = Object.getOwnPropertyDescriptor(OrigPC.prototype, prop);
          if (d && d.get) {
            Object.defineProperty(pc, prop, {
              get: function() { return wrapDesc(d.get.call(this)); },
              configurable: true
            });
          }
        } catch(e) {}
      });

      // setLocalDescription 入参去 IP
      try {
        var origSLD = pc.setLocalDescription.bind(pc);
        pc.setLocalDescription = function(desc) { return origSLD(wrapDesc(desc)); };
      } catch(e) {}

      // createOffer / createAnswer 结果去 IP
      ["createOffer", "createAnswer"].forEach(function(m) {
        try {
          var orig = pc[m].bind(pc);
          pc[m] = function() {
            var r = orig.apply(pc, arguments);
            if (r && typeof r.then === "function") return r.then(wrapDesc);
            return r;
          };
        } catch(e) {}
      });

      // addEventListener("icecandidate") 过滤非 relay
      var origAddEL = pc.addEventListener.bind(pc);
      pc.addEventListener = function(type, listener, options) {
        if (type === "icecandidate" && typeof listener === "function") {
          return origAddEL(type, function(e) { if (isRelay(e.candidate)) return listener.call(this, e); }, options);
        }
        return origAddEL(type, listener, options);
      };

      // onicecandidate 属性赋值（大量检测站用这种写法，旧版漏拦 → 这是移动端泄露的主因之一）
      var _onic = null, _wrap = null;
      try {
        Object.defineProperty(pc, "onicecandidate", {
          get: function() { return _onic; },
          set: function(fn) {
            if (_wrap) { try { pc.removeEventListener("icecandidate", _wrap); } catch(e) {} }
            _onic = fn; _wrap = null;
            if (typeof fn === "function") {
              _wrap = function(e) { if (isRelay(e.candidate)) return fn.call(pc, e); };
              origAddEL("icecandidate", _wrap, false);
            }
          },
          configurable: true
        });
      } catch(e) {}

      return pc;
    }
    HookedPC.prototype = OrigPC.prototype;
    if (OrigPC.generateCertificate) {
      try { HookedPC.generateCertificate = OrigPC.generateCertificate.bind(OrigPC); } catch(e) {}
    }

    win.RTCPeerConnection = HookedPC;
    if (win.webkitRTCPeerConnection) win.webkitRTCPeerConnection = HookedPC;
    if (win.mozRTCPeerConnection)    win.mozRTCPeerConnection = HookedPC;

    /* ---- iframe 防护：对子窗口递归套用同一 hook ---- */
    function hookFrameWin(w) { try { if (w && w !== win && !w.__webrtcGfwHooked) rtcHook(w); } catch(e) {} }

    if (typeof win.HTMLIFrameElement !== "undefined") {
      try {
        var ifrDesc = Object.getOwnPropertyDescriptor(win.HTMLIFrameElement.prototype, "contentWindow");
        if (ifrDesc && ifrDesc.configurable && ifrDesc.get) {
          Object.defineProperty(win.HTMLIFrameElement.prototype, "contentWindow", {
            get: function() { var w = ifrDesc.get.call(this); hookFrameWin(w); return w; },
            configurable: true
          });
        }
      } catch(e) {}
    }

    var doc = win.document;
    if (doc) {
      try {
        var observer = new win.MutationObserver(function(muts) {
          for (var i = 0; i < muts.length; i++) {
            var nodes = muts[i].addedNodes;
            for (var j = 0; j < nodes.length; j++) {
              var el = nodes[j];
              if (el && el.tagName === "IFRAME") {
                try {
                  el.addEventListener("load", function() { hookFrameWin(this.contentWindow); }, { once: true });
                  hookFrameWin(el.contentWindow);
                } catch(e) {}
              }
            }
          }
        });
        if (doc.documentElement) observer.observe(doc.documentElement, { childList: true, subtree: true });
      } catch(e) {}
      try {
        var existing = doc.querySelectorAll("iframe");
        for (var k = 0; k < existing.length; k++) hookFrameWin(existing[k].contentWindow);
      } catch(e) {}
    }
  } catch(e) {}
}

/**
 * 强防护 WebRTC：直接 hook + 注入双保险，最后以彻底移除 API 兜底
 */
function blockWebRTC() {
  var pageWin = (typeof unsafeWindow !== 'undefined' && unsafeWindow) ? unsafeWindow : window;
  var hooked = false;

  // 路径 1：直接 hook 页面 window（CSP 友好，Via 页内引擎 / TM unsafeWindow 均命中）
  try { rtcHook(pageWin); hooked = !!pageWin.__webrtcGfwHooked; } catch(e) {}

  // 路径 2：序列化注入到页面真实上下文（隔离环境引擎补充；被 CSP 拦截会静默失败）
  try {
    const s = document.createElement('script');
    s.textContent = '(' + rtcHook.toString() + ')(window);';
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  } catch(e) {}

  // 路径 3：两条路径都没能 hook（极端隔离 + CSP 双拦），彻底移除 API 兜底
  if (!hooked) {
    try {
      ['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection'].forEach(function(p) {
        try { Object.defineProperty(pageWin, p, { value: undefined, configurable: false, writable: false }); } catch(e) {}
      });
    } catch(e) {}
    log('BLOCKED (remove-API fallback) on', window.location.hostname);
    return;
  }
  log('WebRTC PROTECTED (relay+SDP+onicecandidate+iframe) on', window.location.hostname);
}
 
function parseGFWList(raw) {
  const domains = new Set();
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('!') || t.startsWith('[') || t.startsWith('@@')) continue;
    let d = null;
    if (t.startsWith('||'))                                           d = t.slice(2).replace(/[\^\/\?].*$/, '').toLowerCase();
    else if (t.startsWith('|https://') || t.startsWith('|http://')) {
      const noScheme = t.slice(t.indexOf('://', 1) + 3);
      d = noScheme.replace(/[\/\?#:].*$/, '').toLowerCase();
    }
    else if (t.startsWith('.'))                                        d = t.slice(1).toLowerCase();
    else if (!t.includes('/') && !t.includes('*') && !t.includes(' ') && t.includes('.')) d = t.toLowerCase();
    if (d && !d.startsWith('.') && !d.includes('*') && d.includes('.')) domains.add(d);
  }
  return domains;
}
 
function matchesDomain(hostname, domains) {
  hostname = hostname.toLowerCase().replace(/^www\./, '');
  if (domains.has(hostname)) return true;
  let idx = hostname.indexOf('.');
  while (idx !== -1) {
    const parent = hostname.slice(idx + 1);
    if (domains.has(parent)) return true;
    idx = hostname.indexOf('.', idx + 1);
  }
  return false;
}
 
function getCustomDomains() {
  try { return new Set(JSON.parse(GM_getValue(CONFIG.CUSTOM_KEY, '[]'))); }
  catch (_) { return new Set(); }
}
 
function saveCustomDomains(set) {
  GM_setValue(CONFIG.CUSTOM_KEY, JSON.stringify(Array.from(set)));
}
 
/* ══════════════════════════════════════════════════════════════
   决策
   ══════════════════════════════════════════════════════════════ */
function decideSyncFirst() {
  const href     = window.location.href;
  const hostname = window.location.hostname;
 
  if (CONFIG.FORCE_ALLOW.some(u => href.startsWith(u))) {
    log('FORCE_ALLOW: 放行');
    return true;
  }
 
  const custom = getCustomDomains();
  if (matchesDomain(hostname, custom)) {
    log('自定义列表命中: 开启防护');
    blockWebRTC();
    return true;
  }
 
  return false;
}
 
function decideWithGFW(gfwDomains) {
  const hostname = window.location.hostname;
  if (gfwDomains && matchesDomain(hostname, gfwDomains)) {
    log('GFWList 命中: 开启防护');
    blockWebRTC();
  } else {
    log('未命中任何规则: 放行');
  }
}
 
/* ══════════════════════════════════════════════════════════════
   网络拉取（含重试）
   ══════════════════════════════════════════════════════════════ */
function fetchWithRetry(retriesLeft, onDone) {
  GM_xmlhttpRequest({
    method: 'GET',
    url: CONFIG.GFWLIST_URL,
    timeout: 12000,
    onload(res) {
      try {
        const domains = parseGFWList(atob(res.responseText.trim()));
        GM_setValue(CONFIG.CACHE_KEY,      JSON.stringify(Array.from(domains)));
        GM_setValue(CONFIG.CACHE_TIME_KEY, Date.now());
        onDone && onDone(domains);
      } catch (e) {
        console.warn('[WebRTC-GFW] 解析失败', e);
        if (retriesLeft > 0) fetchWithRetry(retriesLeft - 1, onDone);
        else onDone && onDone(null);
      }
    },
    onerror()   { if (retriesLeft > 0) fetchWithRetry(retriesLeft - 1, onDone); else onDone && onDone(null); },
    ontimeout() { if (retriesLeft > 0) fetchWithRetry(retriesLeft - 1, onDone); else onDone && onDone(null); },
  });
}
 
function fetchAndCache(onDone) {
  fetchWithRetry(2, onDone);
}
 
/* ══════════════════════════════════════════════════════════════
   主流程
   ══════════════════════════════════════════════════════════════ */
function main() {
  const alreadyDecided = decideSyncFirst();
  if (alreadyDecided) return;
 
  const now        = Date.now();
  const cachedRaw  = GM_getValue(CONFIG.CACHE_KEY,      null);
  const cachedTime = GM_getValue(CONFIG.CACHE_TIME_KEY, 0);
  const ttl        = getCacheTTL();
  const age        = now - cachedTime;
 
  const cachedDomains = cachedRaw ? new Set(JSON.parse(cachedRaw)) : null;
  gfwCacheDomains = cachedDomains;
 
  if (cachedDomains && age < ttl) {
    decideWithGFW(cachedDomains);
    if (age > ttl * 0.8) fetchAndCache(null);
  } else if (cachedDomains) {
    decideWithGFW(cachedDomains);
    fetchAndCache(null);
  } else {
    fetchAndCache(domains => {
      if (domains) {
        gfwCacheDomains = domains;
        decideWithGFW(domains);
      }
    });
  }
}
 
/* ══════════════════════════════════════════════════════════════
   油猴菜单（每条单独 try/catch，一条失败不影响其余）
   ══════════════════════════════════════════════════════════════ */
function safeMenu(label, fn) {
  try { GM_registerMenuCommand(label, fn); } catch(e) { console.error('[WebRTC-GFW] 菜单注册失败:', label, e); }
}
 
/** 轻提示，不阻塞操作，2 秒自动消失 */
function toast(msg) {
  try {
    const el = document.createElement('div');
    el.textContent = msg;
    Object.assign(el.style, {
      position: 'fixed', bottom: '24px', left: '50%', transform: 'translateX(-50%)',
      background: 'rgba(0,0,0,0.75)', color: '#fff', padding: '8px 18px',
      borderRadius: '20px', fontSize: '14px', zIndex: '2147483647',
      pointerEvents: 'none', whiteSpace: 'nowrap',
      transition: 'opacity 0.4s', opacity: '1',
    });
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 400); }, 2000);
  } catch(_) {}
}
 
safeMenu('➕ 管理自定义屏蔽域名', () => {
  const custom = getCustomDomains();
  const listText = custom.size === 0
    ? '（暂无自定义域名）'
    : Array.from(custom).map((d, i) => `  ${i + 1}. ${d}`).join('\n');
  const msg = `📋 当前自定义屏蔽域名（${custom.size} 条）：\n${listText}\n\n` +
              `操作说明：\n  • 添加：输入域名（如 example.com）\n  • 删除：输入 -example.com`;
  const input = prompt(msg, '');
  if (input === null) return;
  const val = input.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:.*$/, '').replace(/^www\./, '');
  if (!val) return;
  if (val.startsWith('-')) {
    const target = val.slice(1);
    if (custom.has(target)) { custom.delete(target); saveCustomDomains(custom); alert(`✅ 已删除：${target}`); }
    else alert(`⚠️ 未找到：${target}`);
  } else {
    if (!val.includes('.')) { alert('❌ 请输入合法域名'); return; }
    if (custom.has(val)) { alert(`ℹ️ 已存在：${val}`); return; }
    custom.add(val); saveCustomDomains(custom);
    alert(`✅ 已添加：${val}\n当前共 ${custom.size} 条自定义规则`);
  }
});
 
safeMenu('🚫 屏蔽当前网站 WebRTC', () => {
  const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
  const custom = getCustomDomains();
  if (custom.has(hostname)) { alert(`ℹ️ "${hostname}" 已在列表中`); return; }
  custom.add(hostname); saveCustomDomains(custom);
  location.reload();
});
 
safeMenu('✅ 解除当前网站屏蔽', () => {
  const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
  const custom = getCustomDomains();
 
  // 找出列表里所有会命中当前域名的条目（精确匹配 + 父域匹配）
  const toRemove = Array.from(custom).filter(entry => {
    if (hostname === entry) return true;
    return hostname.endsWith('.' + entry);
  });
 
  if (toRemove.length === 0) { alert(`ℹ️ "${hostname}" 不在列表中`); return; }
 
  toRemove.forEach(entry => custom.delete(entry));
  saveCustomDomains(custom);
 
  // 第一条用 alert 告知结果，多余的条目用 toast 静默提示
  alert(`✅ 已移除：${toRemove[0]}，刷新后生效`);
  toRemove.slice(1).forEach(entry => toast(`同时移除父域：${entry}`));
});
 
safeMenu('⏱️ 设置缓存时长', () => {
  const current = Number(GM_getValue(CONFIG.TTL_KEY, CONFIG.DEFAULT_TTL_HOURS));
  const input = prompt(`当前缓存 ${current} 小时，请输入新时长 (1-720)：`, String(current));
  if (input === null) return;
  const val = Math.round(Number(input.trim()));
  if (!isFinite(val) || val < 1 || val > 720) { alert('❌ 请输入 1~720 整数'); return; }
  GM_setValue(CONFIG.TTL_KEY, val);
  alert(`✅ 已设为 ${val} 小时`);
});
 
safeMenu('🔄 立即刷新 GFWList', () => {
  fetchAndCache(domains => {
    if (domains) gfwCacheDomains = domains;
    alert(domains ? `✅ 更新成功，共 ${domains.size} 条规则` : '❌ 拉取失败，已重试多次');
  });
});
 
safeMenu('ℹ️ 查看缓存状态', () => {
  const cachedTime = GM_getValue(CONFIG.CACHE_TIME_KEY, 0);
  const cachedRaw  = GM_getValue(CONFIG.CACHE_KEY, null);
  const custom     = getCustomDomains();
  if (!cachedRaw) { alert('尚未建立缓存，请手动刷新 GFWList'); return; }
  const ttl       = getCacheTTL();
  const age       = Date.now() - cachedTime;
  const gfwDomains = gfwCacheDomains || new Set(JSON.parse(cachedRaw));
  const hostname  = window.location.hostname;
  const forceAllow = CONFIG.FORCE_ALLOW.some(u => window.location.href.startsWith(u));
  const customHit  = matchesDomain(hostname, custom);
  const gfwHit     = matchesDomain(hostname, gfwDomains);
  let status = '✅ 正常';
  if (forceAllow) status = '✅ 强制放行';
  else if (customHit) status = '🛡️ 防护中（自定义）';
  else if (gfwHit) status = '🛡️ 防护中（GFWList）';
  alert(
    `🌐 当前网站：${hostname}\n  WebRTC：${status}\n\n` +
    `📊 GFWList 缓存：${gfwDomains.size} 条，已缓存 ${Math.floor(age/3600000)}h，剩余约 ${Math.ceil((ttl-age)/3600000)}h\n` +
    `📝 自定义域名：${custom.size} 条${custom.size ? '\n  ' + Array.from(custom).join(', ') : ''}`
  );
});
 
safeMenu('🗑 清除 GFWList 缓存', () => {
  GM_setValue(CONFIG.CACHE_KEY, null);
  GM_setValue(CONFIG.CACHE_TIME_KEY, 0);
  gfwCacheDomains = null;
  alert('缓存已清除');
});
 
safeMenu('🐛 切换调试日志', () => {
  debugMode = !debugMode;
  GM_setValue('debug_mode_v2', debugMode);
  alert('调试日志已' + (debugMode ? '开启' : '关闭'));
});
 
/* ══════════════════════════════════════════════════════════════
   启动
   ══════════════════════════════════════════════════════════════ */
main();