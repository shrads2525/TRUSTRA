const form = document.getElementById("analyzeForm");
const input = document.getElementById("urlInput");
const button = document.getElementById("analyzeButton");
const statusBox = document.getElementById("status");
const report = document.getElementById("report");

function addItems(id, items) {
  const list = document.getElementById(id);
  list.replaceChildren();
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  }
}

function inspectUrl(raw) {
  let value = raw.trim();
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;
  let parsed;
  try { parsed = new URL(value); }
  catch { return { url: value, risk: "Unable to assess", score: 0,
    summary: "This address could not be parsed. Check the URL and try again.",
    findings: ["The URL format appears invalid."],
    recommendations: ["Enter a valid address, such as https://example.com."],
    limitations: "This local demo checks URL patterns only. It cannot guarantee whether a website is safe." }; }

  const host = parsed.hostname.toLowerCase();
  const findings = [];
  const recommendations = [];
  let score = 0;

  if (parsed.protocol !== "https:") {
    score += 15;
    findings.push("The URL does not use HTTPS.");
    recommendations.push("Avoid entering sensitive details unless you trust the website.");
  } else {
    findings.push("The URL uses HTTPS. Encryption does not prove that a website is trustworthy.");
  }
  if (host.includes("@") || parsed.username || parsed.password) {
    score += 20;
    findings.push("The address contains user-information syntax that can make a URL misleading.");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 25;
    findings.push("The hostname is an IP address rather than a regular domain name.");
    recommendations.push("Verify the source carefully before opening an IP-address link.");
  }
  if (host.length > 35) { score += 10; findings.push("The domain name is unusually long."); }
  if ((host.match(/-/g) || []).length >= 3) { score += 10; findings.push("The domain contains several hyphens."); }
  if (host.split(".").length >= 5) { score += 10; findings.push("The hostname has many subdomain levels."); }
  if (/(login|verify|secure|account|update|password|wallet)/i.test(host)) {
    score += 10;
    findings.push("The hostname contains wording sometimes used in account or verification lures.");
  }
  if (/(paypa[l1]|g00gle|app1e|micros0ft|amaz0n)/i.test(host)) {
    score += 25;
    findings.push("The hostname resembles a possible lookalike spelling of a known brand.");
    recommendations.push("Check the spelling carefully and visit the official website directly if unsure.");
  }
  score = Math.min(score, 100);
  if (score >= 50) return finish(value, score, "High", "Several warning signs were detected. Treat this link cautiously.", findings, recommendations);
  if (score >= 25) return finish(value, score, "Medium", "Some warning signs were detected. Check the domain and the source before proceeding.", findings, recommendations);
  return finish(value, score, "Lower", "Few basic warning signs were detected, but that does not prove the website is safe.", findings, recommendations);
}
function finish(url, score, risk, summary, findings, recommendations) {
  if (!findings.length) findings.push("No basic URL warning signs were detected by these checks.");
  if (!recommendations.length) recommendations.push("Confirm the sender and domain through a trusted channel.", "Do not enter sensitive information unless you are sure the website is legitimate.");
  return { url, score, risk, summary, findings, recommendations,
    limitations: "TRUSTRA uses local, rule-based URL checks only. It does not visit the website or query live threat-intelligence databases. The score is not a guarantee that a link is safe or malicious." };
}
form.addEventListener("submit", event => {
  event.preventDefault();
  const value = input.value.trim();
  if (!value) { statusBox.textContent = "Please enter a website address first."; return; }
  button.disabled = true;
  button.firstChild.textContent = "Checking ";
  statusBox.textContent = "Inspecting URL structure…";
  try {
    const data = inspectUrl(value);
    document.getElementById("riskTitle").textContent = data.risk + " risk indicators";
    const badge = document.getElementById("scoreBadge");
    badge.textContent = "Score: " + data.score + "/100";
    badge.className = "score-badge " + data.risk.toLowerCase();
    document.getElementById("summary").textContent = data.summary;
    addItems("findings", data.findings);
    addItems("recommendations", data.recommendations);
    document.getElementById("limitations").textContent = data.limitations;
    document.getElementById("meta").textContent = "Checked: " + data.url;
    report.hidden = false;
    statusBox.textContent = "Analysis complete.";
    report.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    statusBox.textContent = "Sorry, this URL could not be checked. Please verify the address and try again.";
    console.error(error);
  } finally {
    button.disabled = false;
    button.firstChild.textContent = "Analyze URL ";
  }
});
