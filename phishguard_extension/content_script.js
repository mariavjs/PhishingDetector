// content_script.js (debug)
console.log("[CS] content script injected on", location.href);

browser.runtime.onMessage.addListener((msg) => {
  console.log("[CS] runtime message:", msg);
  if (msg.type === "phish_warning") {
    showBanner(msg.payload);
  }
});

function showBanner(payload) {
  console.log("[CS] showBanner payload:", payload);
  if (document.getElementById("phishguard-banner")) return;
  const d = document.createElement("div");
  d.id = "phishguard-banner";
  d.style.position = "fixed";
  d.style.top = "0";
  d.style.left = "0";
  d.style.right = "0";
  d.style.zIndex = "2147483647";
  d.style.padding = "10px";
  d.style.background = payload && payload.is_suspicious ? "#ff4b4b" : "#ffd966";
  d.innerText = `PhishGuard DEBUG — score: ${payload ? payload.score : "?"} — suspeito: ${!!(payload && payload.is_suspicious)}`;
  const b = document.createElement("button");
  b.innerText = "Fechar";
  b.onclick = () => d.remove();
  d.appendChild(b);
  document.body.appendChild(d);
}

// hover -> pergunta ao background
document.addEventListener("mouseover", (ev) => {
  const a = ev.target.closest("a");
  if (!a || !a.href) return;
  console.log("[CS] hover link:", a.href);
  browser.runtime.sendMessage({ action: "check_link", url: a.href })
    .then(resp => {
      console.log("[CS] check_link resp:", resp);
      if (resp && resp.is_suspicious) {
        a.style.outline = "3px solid red";
        a.title = `Link suspeito (score ${resp.score})`;
      }
    })
    .catch(e => console.error("[CS] sendMessage error:", e));
});
