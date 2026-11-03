// ============================================================
//  Phishing Detector - popup.js
// ============================================================

document.addEventListener("DOMContentLoaded", async () => {
  const content = document.getElementById("main-content");

  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      content.innerHTML = `<div class="loading">No active tab found.</div>`;
      return;
    }

    const key = `tab_${tab.id}`;
    const result = await chrome.storage.local.get(key);
    const data = result[key];

    if (!data) {
      content.innerHTML = `
        <div class="loading">
          No data yet.<br/>Reload the page to scan it.
        </div>`;
      return;
    }

    const { domain, risk, reasons } = data;

    // Determine level
    let level, cardClass, verdict;
    if (risk >= 70) {
      level = "🚨 HIGH RISK";
      cardClass = "danger";
      verdict = "Likely a phishing site!";
    } else if (risk >= 35) {
      level = "⚠️ SUSPICIOUS";
      cardClass = "warning";
      verdict = "Proceed with caution";
    } else {
      level = "✅ SAFE";
      cardClass = "safe";
      verdict = "No major threats detected";
    }

    content.innerHTML = `
      <div class="domain">Scanned: <span>${domain || tab.url}</span></div>

      <div class="score-card ${cardClass}">
        <div class="score-label">${level}</div>
        <div>
          <span class="score-number">${risk}</span>
          <span class="score-max"> / 100</span>
        </div>
        <div class="score-verdict">${verdict}</div>
      </div>

      <div class="reasons-title">Detection Reasons</div>
      <div class="reasons-list">
        ${
          reasons.length > 0
            ? reasons.map(r => `<div class="reason-item">${r}</div>`).join("")
            : `<div class="no-reasons">No suspicious signals found.</div>`
        }
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="loading">Error: ${err.message}</div>`;
  }
});
