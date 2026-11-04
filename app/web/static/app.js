/* HCVF console - small, dependency-free enhancements. */
(function () {
  "use strict";

  const HC = {};

  HC.theme = function () {
    const stored = localStorage.getItem("hcvf-theme");
    if (stored) document.documentElement.setAttribute("data-theme", stored);
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.addEventListener("click", function () {
      const current = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", current);
      localStorage.setItem("hcvf-theme", current);
    });
  };

  HC.liveFeed = function () {
    const feed = document.getElementById("event-feed");
    const dot = document.getElementById("live-dot");
    if (!feed) return;
    const url = feed.getAttribute("data-sse");
    if (!url || typeof EventSource === "undefined") return;

    const seen = new Set(
      Array.from(feed.querySelectorAll("[data-event-id]")).map(function (node) {
        return node.getAttribute("data-event-id");
      })
    );
    const source = new EventSource(url);
    source.onopen = function () { if (dot) dot.classList.add("on"); };
    source.onerror = function () { if (dot) dot.classList.remove("on"); };

    source.onmessage = function (message) {
      let payload;
      try { payload = JSON.parse(message.data); } catch (error) { return; }
      const text = payload.type + "|" + payload.at + "|" + payload.message;
      if (seen.has(text)) return;
      seen.add(text);
      const placeholder = feed.querySelector(".empty");
      if (placeholder) placeholder.remove();
      const row = document.createElement("li");
      row.setAttribute("data-event-id", text);
      row.className = String(payload.type || "").split(".")[0];
      const time = document.createElement("span");
      time.className = "mono small";
      time.textContent = (payload.at || "").slice(11, 19);
      const main = document.createElement("span");
      main.className = "feed-main";
      main.textContent = payload.message || "";
      const kind = document.createElement("span");
      kind.className = "muted small mono";
      kind.textContent = payload.type || "";
      row.appendChild(time);
      row.appendChild(main);
      row.appendChild(kind);
      feed.appendChild(row);
      feed.scrollTop = feed.scrollHeight;
    };

    source.addEventListener("end", function () {
      if (dot) dot.classList.remove("on");
      source.close();
    });
  };

  HC.relativeTimes = function () {
    document.querySelectorAll("[data-ts]").forEach(function (node) {
      const stamp = node.getAttribute("data-ts");
      if (!stamp) return;
      const value = Date.parse(stamp);
      if (Number.isNaN(value)) return;
      const seconds = Math.round((Date.now() - value) / 1000);
      if (seconds < 60) node.textContent = seconds + "s ago";
      else if (seconds < 3600) node.textContent = Math.round(seconds / 60) + "m ago";
      else if (seconds < 86400) node.textContent = Math.round(seconds / 3600) + "h ago";
      else node.textContent = Math.round(seconds / 86400) + "d ago";
    });
  };

  document.addEventListener("DOMContentLoaded", function () {
    HC.theme();
    HC.liveFeed();
    HC.relativeTimes();
  });

  window.HCVF = HC;
})();
