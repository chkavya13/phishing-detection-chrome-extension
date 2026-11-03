// ============================================================
//  Phishing Detector - background.js (Service Worker)
// ============================================================

chrome.runtime.onInstalled.addListener(() => {
  console.log("✅ Phishing Detector installed.");
});

// Store the latest result per tab so popup can read it
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PHISHING_RESULT" && sender.tab) {
    chrome.storage.local.set({
      [`tab_${sender.tab.id}`]: {
        domain: message.domain,
        risk: message.risk,
        reasons: message.reasons,
        timestamp: Date.now()
      }
    });
  }
});

// Clean up stored data when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
