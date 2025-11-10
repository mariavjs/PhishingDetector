// background.js (debug)
console.log("[BG] background.js loaded");

const API_URL = "http://127.0.0.1:5000/analyze";
const BLOCK_THRESHOLD_DEFAULT = 65; // pontuação a partir da qual bloqueia (ajustável)

async function getSettings() {
  const s = await browser.storage.local.get({ whitelist: [], threshold: BLOCK_THRESHOLD_DEFAULT, enabled: true, auto_block: false });
  console.log("[BG] settings:", s);
  return s;
}

async function fetchAnalyze(url) {
  console.log("[BG] fetchAnalyze ->", url);
  try {
    const resp = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    console.log("[BG] fetch status", resp.status);
    if (!resp.ok) {
      const text = await resp.text().catch(()=>"(no body)");
      console.warn("[BG] fetch non-ok:", resp.status, text);
      return { error: `HTTP ${resp.status}` };
    }
    const j = await resp.json().catch(()=>null);
    console.log("[BG] fetch json:", j);
    return j || { error: "no-json" };
  } catch (e) {
    console.error("[BG] fetch error:", e);
    return { error: e.toString() };
  }
}

async function handleTabUpdate(tabId, changeInfo, tab) {
  try {
    if (changeInfo.status !== "complete") return;
    console.log("[BG] tab updated:", tabId, tab.url);
    const url = tab.url;
    if (!url || !url.startsWith("http")) return;

    const settings = await getSettings();
    if (!settings.enabled) return;

    const hostname = new URL(url).hostname;
    if (settings.whitelist && settings.whitelist.includes(hostname)) {
      console.log("[BG] hostname whitelisted:", hostname);
      return;
    }

    const res = await fetchAnalyze(url);
    if (res.error) {
      console.warn("[BG] Analyzer error:", res.error);
      return;
    }

    const score = res.score || 0;
    const suspicious = res.is_suspicious === true;
    const threshold = settings.threshold || BLOCK_THRESHOLD_DEFAULT;

    if (suspicious || score >= threshold) {
      console.log("[BG] suspicious detected:", score, suspicious);
      browser.notifications.create({
        "type": "basic",
        "iconUrl": "icons/icon48.png",
        "title": "PhishGuard — Página suspeita",
        "message": `Score ${score}/100 — ${suspicious ? "Suspeito" : "Possível risco"}`
      });

      if (score >= threshold && settings.auto_block) {
        try {
          await browser.tabs.update(tabId, { url: "about:blank" });
        } catch (e) {
          console.warn("[BG] Falha ao bloquear:", e);
        }
      }

      try {
        await browser.tabs.sendMessage(tabId, { type: "phish_warning", payload: res });
        console.log("[BG] sent phish_warning to tab", tabId);
      } catch (e) {
        console.log("[BG] could not sendMessage (maybe no content script):", e);
      }
    } else {
      console.log("[BG] page not suspicious:", score);
    }
  } catch (e) {
    console.error("[BG] handleTabUpdate error:", e);
  }
}

browser.runtime.onMessage.addListener((msg, sender) => {
  console.log("[BG] runtime message:", msg, "from", sender && sender.tab ? sender.tab.id : null);
  if (msg.action === "check_link" && msg.url) {
    return fetchAnalyze(msg.url);
  }
});

browser.tabs.onUpdated.addListener(handleTabUpdate);
