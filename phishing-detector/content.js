// ============================================================
//  Phishing Detector - content.js v3.0
//  Advanced phishing detection with typosquatting, homograph,
//  brand-in-subdomain, and GITAM-specific protection.
// ============================================================

(function () {
  if (window.__phishingDetectorRan) return;
  window.__phishingDetectorRan = true;

  const url = window.location.href.toLowerCase();
  const domain = window.location.hostname.toLowerCase();
  const protocol = window.location.protocol;

  let risk = 0;
  const reasons = [];

  const trustedBrands = [
    { name: "gitam",      official: ["gitam.edu"] },
    { name: "paypal",     official: ["paypal.com"] },
    { name: "amazon",     official: ["amazon.com", "amazon.in"] },
    { name: "google",     official: ["google.com", "google.co.in"] },
    { name: "facebook",   official: ["facebook.com"] },
    { name: "instagram",  official: ["instagram.com"] },
    { name: "apple",      official: ["apple.com"] },
    { name: "microsoft",  official: ["microsoft.com", "live.com", "outlook.com"] },
    { name: "netflix",    official: ["netflix.com"] },
    { name: "sbi",        official: ["sbi.co.in", "onlinesbi.sbi"] },
    { name: "hdfc",       official: ["hdfcbank.com"] },
    { name: "icici",      official: ["icicibank.com"] },
  ];

  const homographMap = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "@": "a", "vv": "w", "rn": "m"
  };

  function normalizeForTypo(str) {
    let normalized = str;
    for (const [fake, real] of Object.entries(homographMap)) {
      normalized = normalized.split(fake).join(real);
    }
    return normalized;
  }

  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++)
        dp[i][j] = a[i-1] === b[j-1]
          ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[a.length][b.length];
  }

  if (protocol === "http:") {
    risk += 25;
    reasons.push("❌ Uses HTTP instead of HTTPS (insecure connection)");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    risk += 35;
    reasons.push("🚨 Website hosted on a raw IP address — major red flag");
  }

  const domainParts = domain.split(".");
  const registeredDomain = domainParts.slice(-2).join(".");
  const subdomains = domainParts.slice(0, -2).join(".");

  for (const brand of trustedBrands) {
    const brandName = brand.name;

    const isOfficial = brand.official.some(
      (od) => domain === od || domain === "www." + od || domain.endsWith("." + od)
    );
    if (isOfficial) continue;

    if (subdomains.includes(brandName)) {
      risk += 50;
      reasons.push(`🚨 "${brandName}" used in subdomain to trick users — not the official site`);
      continue;
    }

    if (registeredDomain.includes(brandName)) {
      risk += 45;
      reasons.push(`🚨 Fake domain impersonating "${brandName}" with extra words`);
      continue;
    }

    const normalizedRegistered = normalizeForTypo(registeredDomain.split(".")[0]);
    if (normalizedRegistered.includes(brandName) && !registeredDomain.split(".")[0].includes(brandName)) {
      risk += 50;
      reasons.push(`🚨 Typosquatting — domain looks like "${brandName}" using character tricks`);
      continue;
    }

    const domainWord = registeredDomain.split(".")[0];
    const distance = levenshtein(domainWord, brandName);
    const similarity = 1 - distance / Math.max(domainWord.length, brandName.length);

    if (similarity >= 0.75 && domainWord !== brandName) {
      risk += 45;
      reasons.push(`🚨 "${domainWord}" looks very similar to "${brandName}" — possible typosquatting`);
    }
  }

  const suspiciousKeywords = [
    "login", "signin", "sign-in", "verify", "secure",
    "account", "update", "banking", "payment", "confirm",
    "wallet", "credential", "password", "reset", "support"
  ];
  suspiciousKeywords.forEach((word) => {
    if (domain.includes(word)) {
      risk += 10;
      reasons.push(`⚠️ Suspicious keyword in domain: "${word}"`);
    }
  });

  if (domainParts.length > 4) {
    risk += 20;
    reasons.push(`⚠️ Too many subdomains — common in phishing URLs`);
  }

  if (/[0-9]/.test(registeredDomain.split(".")[0])) {
    risk += 10;
    reasons.push("⚠️ Domain contains numbers — often used in fake domains");
  }

  if (domain.length > 30) {
    risk += 10;
    reasons.push(`⚠️ Unusually long domain (${domain.length} chars)`);
  }

  const passwordFields = document.querySelectorAll('input[type="password"]');
  const emailOrUserFields = document.querySelectorAll(
    'input[type="email"], input[name*="user"], input[name*="email"], input[placeholder*="email"], input[placeholder*="username"]'
  );
  if (passwordFields.length > 0 && emailOrUserFields.length > 0 && risk > 0) {
    risk += 20;
    reasons.push("🔐 Login form on suspicious domain — do NOT enter your credentials!");
  }

  const suspiciousPaths = ["phishing", "fake", "spoof", "clone", "hack"];
  suspiciousPaths.forEach((p) => {
    if (url.includes(p)) {
      risk += 15;
      reasons.push(`⚠️ Suspicious path in URL: "${p}"`);
    }
  });

  risk = Math.min(risk, 100);

  chrome.runtime.sendMessage({ type: "PHISHING_RESULT", domain, risk, reasons });

  if (risk >= 35) injectWarningBanner(risk, reasons);

  function injectWarningBanner(score, reasonList) {
    if (document.getElementById("phishing-detector-banner")) return;

    const bgColor = score >= 70 ? "#b91c1c" : "#d97706";
    const level = score >= 70 ? "DANGER" : "WARNING";
    const emoji = score >= 70 ? "🚨" : "⚠️";

    const banner = document.createElement("div");
    banner.id = "phishing-detector-banner";
    banner.style.cssText = "all: unset; display: block !important; position: fixed !important; top: 0 !important; left: 0 !important; width: 100% !important; z-index: 2147483647 !important;";

    const inner = document.createElement("div");
    inner.style.cssText = `background: ${bgColor}; color: white; font-family: Arial, sans-serif; padding: 12px 16px; display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); border-bottom: 3px solid rgba(255,255,255,0.3); box-sizing: border-box; width: 100%;`;

    const left = document.createElement("div");
    left.style.cssText = "flex: 1; min-width: 0;";

    const title = document.createElement("div");
    title.style.cssText = "font-size: 15px; font-weight: bold; margin-bottom: 8px; color: white;";
    title.textContent = `${emoji} PHISHING ${level} — Risk Score: ${score}/100`;

    const tags = document.createElement("div");
    tags.style.cssText = "display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px;";
    reasonList.forEach((r) => {
      const tag = document.createElement("span");
      tag.style.cssText = "background: rgba(0,0,0,0.25); padding: 3px 8px; border-radius: 4px; font-size: 12px; color: white; white-space: nowrap; display: inline-block;";
      tag.textContent = r;
      tags.appendChild(tag);
    });

    const footer = document.createElement("div");
    footer.style.cssText = "font-size: 11px; color: rgba(255,255,255,0.8);";
    footer.textContent = "🔒 Phishing Detector Extension · Do NOT enter your password or personal details on this site";

    left.appendChild(title);
    left.appendChild(tags);
    left.appendChild(footer);

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "✕";
    closeBtn.style.cssText = "background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.5); color: white; font-size: 16px; cursor: pointer; border-radius: 6px; padding: 4px 10px; flex-shrink: 0; font-family: Arial;";
    closeBtn.onclick = () => banner.remove();

    inner.appendChild(left);
    inner.appendChild(closeBtn);
    banner.appendChild(inner);

    document.documentElement.insertBefore(banner, document.documentElement.firstChild);
  }

})();