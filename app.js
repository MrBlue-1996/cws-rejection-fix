const manifestInput = document.querySelector("#manifest");
const rejectionInput = document.querySelector("#rejection");
const form = document.querySelector("#triage-form");
const loadDemo = document.querySelector("#load-demo");
const scoreEl = document.querySelector("#score");
const badgeEl = document.querySelector("#risk-badge");
const summaryLine = document.querySelector("#summary-line");
const issuesEl = document.querySelector("#issues");
const copyReport = document.querySelector("#copy-report");
let lastReport = "";

const highRiskPermissions = new Set([
  "cookies",
  "debugger",
  "history",
  "management",
  "nativeMessaging",
  "scripting",
  "tabs",
  "webRequest",
  "webRequestBlocking",
]);

const broadHosts = new Set(["<all_urls>", "http://*/*", "https://*/*", "*://*/*"]);

const rejectionSignals = [
  {
    id: "unnecessary-permissions",
    title: "Reviewer flagged unnecessary permissions",
    policy: "Use of Permissions / least privilege",
    patterns: [
      /permissions? (?:that are )?(?:not|isn't|are not) (?:required|necessary|needed)/i,
      /permissions? need not be requested/i,
      /remove unused permissions?/i,
      /permission(?:s)? (?:are|is) not justified/i,
      /not required for (?:the )?(?:single )?purpose/i,
    ],
  },
  {
    id: "user-data-privacy",
    title: "Reviewer flagged user data privacy",
    policy: "User Data Privacy / disclosure consistency",
    patterns: [
      /user data privacy/i,
      /data use/i,
      /privacy policy/i,
      /personal data/i,
      /data disclosure/i,
      /limited use/i,
    ],
  },
  {
    id: "broad-host-access",
    title: "Reviewer flagged broad host access",
    policy: "Host permissions / narrow access",
    patterns: [
      /all urls/i,
      /all sites/i,
      /host permissions?/i,
      /broad(?:ly)? (?:host|site|url) access/i,
      /access to all websites/i,
    ],
  },
  {
    id: "remote-code",
    title: "Reviewer flagged remote or dynamic code",
    policy: "Remote hosted code / reviewability",
    patterns: [
      /remote hosted code/i,
      /remotely hosted code/i,
      /remote code/i,
      /external javascript/i,
      /unsafe-eval/i,
      /eval\(/i,
    ],
  },
  {
    id: "single-purpose",
    title: "Reviewer flagged single-purpose mismatch",
    policy: "Single purpose / listing consistency",
    patterns: [
      /single purpose/i,
      /narrow and easy-to-understand purpose/i,
      /does not match (?:the )?(?:description|listing|functionality)/i,
      /misleading/i,
    ],
  },
];

const demoManifest = {
  manifest_version: 3,
  name: "Page Helper",
  version: "1.0.0",
  permissions: ["storage", "tabs", "scripting"],
  host_permissions: ["<all_urls>"],
  content_scripts: [
    {
      matches: ["<all_urls>"],
      js: ["content.js"],
    },
  ],
};

function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function addIssue(issues, severity, title, detail, manualReview, policy = "Manual review") {
  issues.push({ severity, title, detail, manualReview, policy });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function requestedHostPermissions(manifest) {
  const permissions = asArray(manifest.permissions).filter((permission) => typeof permission === "string");
  const hostPermissions = asArray(manifest.host_permissions).filter((permission) => typeof permission === "string");
  return [...hostPermissions, ...permissions.filter((permission) => permission.includes("://") || broadHosts.has(permission))];
}

function matchRejectionSignals(rejectionText) {
  return rejectionSignals.filter((signal) => signal.patterns.some((pattern) => pattern.test(rejectionText)));
}

function severityFromSignal(signal, manifest) {
  const permissions = new Set(asArray(manifest.permissions));
  const hosts = requestedHostPermissions(manifest);
  if (signal.id === "broad-host-access" && hosts.some((host) => broadHosts.has(host))) return "high";
  if (signal.id === "unnecessary-permissions" && [...permissions].some((permission) => highRiskPermissions.has(permission))) return "high";
  if (signal.id === "user-data-privacy" && !manifest.homepage_url && !manifest.privacy_policy) return "high";
  if (signal.id === "remote-code") return "high";
  return "medium";
}

function manifestEvidenceFor(signal, manifest) {
  const permissions = new Set(asArray(manifest.permissions));
  const hosts = requestedHostPermissions(manifest);
  const contentScripts = asArray(manifest.content_scripts);

  if (signal.id === "unnecessary-permissions") {
    const highRisk = [...permissions].filter((permission) => highRiskPermissions.has(permission));
    return highRisk.length ? `High-review permissions present: ${highRisk.join(", ")}.` : "The rejection text references permission justification.";
  }
  if (signal.id === "user-data-privacy") {
    return manifest.homepage_url || manifest.privacy_policy
      ? "Manifest has a homepage/privacy signal, but it still needs to match CWS dashboard answers."
      : "No homepage_url or privacy_policy signal found in the manifest.";
  }
  if (signal.id === "broad-host-access") {
    const broad = hosts.filter((host) => broadHosts.has(host));
    return broad.length ? `Broad host access present: ${broad.join(", ")}.` : "The rejection text references host access.";
  }
  if (signal.id === "remote-code") {
    const csp = JSON.stringify(manifest.content_security_policy || {});
    return /unsafe-eval|https?:\/\/[^"']+\.js/i.test(csp)
      ? "The manifest content_security_policy has a dynamic/remote-code signal."
      : "The rejection text references remote or dynamic code; source package needs manual review.";
  }
  if (signal.id === "single-purpose") {
    return contentScripts.length || permissions.size ? "Manifest behavior and listing copy need to be compared manually." : "The rejection text references listing/functionality mismatch.";
  }
  return "Manual comparison needed.";
}

function scan(manifest, rejectionText) {
  const issues = [];
  const permissions = new Set(asArray(manifest.permissions));
  const hostPermissions = new Set(requestedHostPermissions(manifest));
  const contentScripts = asArray(manifest.content_scripts);
  const matchedSignals = matchRejectionSignals(rejectionText);
  const hasSignal = (id) => matchedSignals.some((signal) => signal.id === id);

  for (const signal of matchedSignals) {
    addIssue(
      issues,
      severityFromSignal(signal, manifest),
      signal.title,
      `${signal.policy}. ${manifestEvidenceFor(signal, manifest)}`,
      "Manual triage maps the reviewer sentence to the exact manifest field, listing text, and privacy disclosure.",
      signal.policy
    );
  }

  for (const permission of permissions) {
    if (!highRiskPermissions.has(permission)) continue;
    if (hasSignal("unnecessary-permissions")) continue;
    if (permission === "tabs" || issues.some((issue) => issue.title.includes(permission))) continue;
    addIssue(
      issues,
      permission === "scripting" && [...hostPermissions].some((host) => broadHosts.has(host)) ? "high" : "medium",
      `Review permission: ${permission}`,
      `${permission} is commonly reviewed for least-privilege and user-data fit.`,
      "Manual triage checks whether this permission is actually required and how it should be justified or reduced.",
      "Use of Permissions / least privilege"
    );
  }

  if (permissions.has("tabs") && !hasSignal("unnecessary-permissions")) {
    addIssue(
      issues,
      "medium",
      "Tabs permission needs manual review",
      "The tabs permission is often reviewed when sensitive tab metadata access is not clearly tied to a user-facing feature.",
      "Manual triage checks the actual tab API usage and decides whether the permission should be kept, reduced, or replaced.",
      "Tabs API / sensitive tab fields"
    );
  }

  const broadHostHits = [...hostPermissions].filter((host) => broadHosts.has(host));
  if (broadHostHits.length && !hasSignal("broad-host-access")) {
    addIssue(
      issues,
      "high",
      "Broad host access",
      `host_permissions includes ${broadHostHits.join(", ")}.`,
      "Manual triage checks whether broad access is justified by the core feature or should be narrowed before resubmission.",
      "Host permissions / narrow access"
    );
  }

  for (const script of contentScripts) {
    const matches = asArray(script.matches).filter((match) => broadHosts.has(match));
    if (!matches.length) continue;
    addIssue(
      issues,
      "medium",
      "Broad content script match",
      `content_scripts.matches includes ${matches.join(", ")}.`,
      "Manual triage checks whether this match pattern is necessary for the extension's single purpose.",
      "Content scripts / narrow access"
    );
  }

  const hasPrivacySignal = manifest.homepage_url || manifest.privacy_policy;
  if (!hasPrivacySignal && !hasSignal("user-data-privacy")) {
    addIssue(
      issues,
      "medium",
      "Privacy disclosure needs review",
      "No homepage_url or privacy_policy signal was found in the manifest.",
      "Manual triage drafts privacy wording that matches permissions, code behavior, and CWS dashboard answers.",
      "User Data Privacy / disclosure consistency"
    );
  }

  const csp = JSON.stringify(manifest.content_security_policy || {});
  if (/unsafe-eval|https?:\/\/[^"']+\.js/i.test(csp)) {
    addIssue(
      issues,
      "high",
      "Remote or dynamic code risk",
      "The manifest content security policy suggests eval or externally hosted JavaScript.",
      "Manual triage checks the submitted package for remote-code or dynamic-code review issues.",
      "Remote hosted code / reviewability"
    );
  }

  if (issues.length === 0) {
    addIssue(
      issues,
      "low",
      "No obvious manifest-level rejection trigger",
      "The likely issue may be listing copy, privacy dashboard answers, package files, or reviewer flow.",
      "Manual triage needs the full rejection text and submitted package to narrow the cause.",
      "Manual review"
    );
  }

  return issues;
}

function issueSummary(issues) {
  const high = issues.filter((issue) => issue.severity === "high").length;
  const medium = issues.filter((issue) => issue.severity === "medium").length;
  if (high > 0) return `${high} high-signal issue${high > 1 ? "s" : ""}. Full triage is needed before another resubmit.`;
  if (medium > 0) return `${medium} review issue${medium > 1 ? "s" : ""}. Manual review can decide if it is actionable.`;
  return "No obvious manifest-level trigger found. Review listing text and submitted package contents.";
}

function scoreFor(issues) {
  return Math.max(
    0,
    100 -
      issues.reduce((total, issue) => {
        if (issue.severity === "high") return total + 14;
        if (issue.severity === "medium") return total + 7;
        return total + 3;
      }, 0)
  );
}

function plainReport(issues, score) {
  const lines = [
    `Chrome Web Store rejection triage - free scan`,
    `Risk score: ${score}/100`,
    ``,
    `Review signals:`,
  ];
  issues.forEach((issue, index) => {
    lines.push(`${index + 1}. [${issue.severity.toUpperCase()}] ${issue.title}`);
    lines.push(`   Policy signal: ${issue.policy}`);
    lines.push(`   Evidence: ${issue.detail}`);
    lines.push(`   Manual review: ${issue.manualReview}`);
  });
  lines.push(
    ``,
    `Full triage includes exact manifest changes, privacy text, and a reviewer note.`,
    `Contact: rwestgate602@gmail.com for full triage ($29).`
  );
  return lines.join("\n");
}

function render(issues) {
  const score = scoreFor(issues);
  scoreEl.textContent = `Risk score: ${score}/100`;
  const level = score < 60 ? "high" : score < 85 ? "medium" : "low";
  badgeEl.className = `badge ${level}`;
  badgeEl.textContent = level === "high" ? "High risk" : level === "medium" ? "Needs work" : "Low risk";
  summaryLine.textContent = issueSummary(issues);

  issuesEl.className = "issues";
  issuesEl.innerHTML = issues
    .map(
      (issue) => `
        <article class="issue ${issue.severity}">
          <div class="issue-title">
            <span>${escapeHtml(issue.title)}</span>
            <span class="badge ${issue.severity}">${issue.severity}</span>
          </div>
          <p>${escapeHtml(issue.detail)}</p>
          <p><strong>Manual review:</strong> ${escapeHtml(issue.manualReview)}</p>
        </article>
      `
    )
    .join("");

  lastReport = plainReport(issues, score);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  let manifest;
  try {
    manifest = JSON.parse(manifestInput.value);
  } catch {
    scoreEl.textContent = "Invalid manifest JSON";
    badgeEl.className = "badge high";
    badgeEl.textContent = "Parse error";
    summaryLine.textContent = "The manifest could not be parsed.";
    issuesEl.className = "issues empty";
    issuesEl.textContent = "Fix the JSON and run triage again.";
    lastReport = "";
    return;
  }

  render(scan(manifest, rejectionInput.value));
});

loadDemo.addEventListener("click", () => {
  manifestInput.value = JSON.stringify(demoManifest, null, 2);
  rejectionInput.value =
    "Your item was rejected because it requests permissions that are not required. Please review tabs, scripting, and broad host access. User Data Privacy disclosures must match the extension behavior.";
  render(scan(demoManifest, rejectionInput.value));
});

window.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }
});

copyReport.addEventListener("click", async () => {
  if (!lastReport) return;
  await navigator.clipboard.writeText(lastReport);
  copyReport.innerHTML = '<i data-lucide="check"></i> Copied';
  if (window.lucide) window.lucide.createIcons();
  setTimeout(() => {
    copyReport.innerHTML = '<i data-lucide="copy"></i> Copy report';
    if (window.lucide) window.lucide.createIcons();
  }, 1400);
});
