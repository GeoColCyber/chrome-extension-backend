import express from "express";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SAFE_BROWSING_KEY = process.env.API_KEY;
const VIRUS_TOTAL_KEY = process.env.Virus_Key;

const ONE_DAY_SECONDS = 24 * 60 * 60;

app.get("/", (req, res) => {
  res.json({ ok: true, service: "guardis-backend" });
});

function unixNow() {
  return Math.floor(Date.now() / 1000);
}

function toUrlHost(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return "unknown";
  }
}

function toBase64UrlNoPadding(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function parseJsonSafe(text, fallback = {}) {
  try {
    return text ? JSON.parse(text) : fallback;
  } catch {
    return fallback;
  }
}

async function runSafeBrowsingCheck(url, client) {
  if (!SAFE_BROWSING_KEY) {
    throw new Error("Missing API_KEY environment variable");
  }

  const requestBody = {
    client: {
      clientId: client?.clientId || "guardis",
      clientVersion: client?.clientVersion || "1.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    }
  );

  const rawText = await response.text();
  if (!response.ok) {
    throw new Error(`Google Safe Browsing request failed (${response.status}): ${rawText}`);
  }

  const parsed = parseJsonSafe(rawText, {});
  const matches = Array.isArray(parsed.matches) ? parsed.matches : [];
  const threatTypes = [...new Set(matches.map((m) => m.threatType).filter(Boolean))];

  return {
    matches,
    threatTypes,
    safe: matches.length === 0
  };
}

function buildVirusTotalRiskSignals(vt) {
  const signals = [];
  const stats = vt.lastAnalysisStats || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  const undetected = Number(stats.undetected || 0);
  const totalEngines = malicious + suspicious + harmless + undetected;
  const timesSubmitted = Number(vt.timesSubmitted || 0);
  const firstSubmissionDate = typeof vt.firstSubmissionDate === "number" ? vt.firstSubmissionDate : null;
  const ageDays = firstSubmissionDate != null
    ? Math.floor((unixNow() - firstSubmissionDate) / ONE_DAY_SECONDS)
    : null;

  if (malicious > 0) {
    signals.push({
      level: "high",
      code: "vt_malicious_detection",
      message: `${malicious} VirusTotal engines marked this URL as malicious.`
    });
  }

  if (suspicious > 0) {
    signals.push({
      level: "medium",
      code: "vt_suspicious_detection",
      message: `${suspicious} VirusTotal engines marked this URL as suspicious.`
    });
  }

  if (ageDays != null && ageDays >= 0 && ageDays <= 30) {
    signals.push({
      level: "medium",
      code: "recent_first_seen",
      message: `URL first seen ${ageDays} day(s) ago on VirusTotal.`
    });
  }

  if (ageDays != null && ageDays >= 0 && ageDays <= 14 && timesSubmitted > 0 && timesSubmitted <= 5) {
    signals.push({
      level: "high",
      code: "recent_low_history",
      message: `URL appears recently seen (${ageDays} day(s)) with low submission history (${timesSubmitted}), which can match fresh phishing infrastructure.`
    });
  }

  if (typeof vt.reputation === "number" && vt.reputation < 0) {
    signals.push({
      level: "medium",
      code: "negative_reputation",
      message: `VirusTotal reputation is negative (${vt.reputation}).`
    });
  }

  if (totalEngines > 0 && totalEngines < 10) {
    signals.push({
      level: "low",
      code: "limited_coverage",
      message: `Only ${totalEngines} engines reported analysis. Confidence may be limited.`
    });
  }

  return signals;
}

async function runVirusTotalCheck(url) {
  if (!VIRUS_TOTAL_KEY) {
    return {
      enabled: false,
      status: "missing_key",
      message: "VirusTotal key not configured"
    };
  }

  const id = toBase64UrlNoPadding(url);
  const response = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    method: "GET",
    headers: {
      "x-apikey": VIRUS_TOTAL_KEY
    }
  });

  const rawText = await response.text();

  if (response.status === 404) {
    return {
      enabled: true,
      status: "not_found",
      message: "URL not found in VirusTotal dataset"
    };
  }

  if (!response.ok) {
    return {
      enabled: true,
      status: "error",
      message: `VirusTotal request failed (${response.status})`,
      details: rawText
    };
  }

  const parsed = parseJsonSafe(rawText, {});
  const attributes = (parsed.data && parsed.data.attributes) || {};

  const vt = {
    enabled: true,
    status: "ok",
    reputation: typeof attributes.reputation === "number" ? attributes.reputation : null,
    firstSubmissionDate: typeof attributes.first_submission_date === "number" ? attributes.first_submission_date : null,
    lastSubmissionDate: typeof attributes.last_submission_date === "number" ? attributes.last_submission_date : null,
    lastAnalysisDate: typeof attributes.last_analysis_date === "number" ? attributes.last_analysis_date : null,
    timesSubmitted: typeof attributes.times_submitted === "number" ? attributes.times_submitted : null,
    lastAnalysisStats: attributes.last_analysis_stats || {},
    categories: attributes.categories || {}
  };

  vt.riskSignals = buildVirusTotalRiskSignals(vt);
  return vt;
}

app.post("/api", async (req, res) => {
  try {
    const { type, url, client } = req.body || {};

    if (type !== "check-url") {
      return res.status(400).json({ error: "Unsupported request type" });
    }

    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "Missing or invalid url" });
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: "Invalid URL format" });
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.json({
        safe: true,
        matches: [],
        threatTypes: [],
        skipped: true,
        reason: "non_http_url",
        riskSignals: []
      });
    }

    const [safeBrowsing, virusTotal] = await Promise.all([
      runSafeBrowsingCheck(url, client),
      runVirusTotalCheck(url)
    ]);

    const vtStats = (virusTotal && virusTotal.lastAnalysisStats) || {};
    const vtMalicious = Number(vtStats.malicious || 0);
    const vtSuspicious = Number(vtStats.suspicious || 0);
    const vtUnsafe = vtMalicious > 0 || vtSuspicious > 0;

    const threatTypes = [...safeBrowsing.threatTypes];
    if (vtMalicious > 0) threatTypes.push("VIRUSTOTAL_MALICIOUS");
    if (vtSuspicious > 0) threatTypes.push("VIRUSTOTAL_SUSPICIOUS");

    return res.json({
      safe: safeBrowsing.safe && !vtUnsafe,
      matches: safeBrowsing.matches,
      threatTypes: [...new Set(threatTypes)],
      host: toUrlHost(url),
      safeBrowsing: {
        safe: safeBrowsing.safe,
        matchCount: safeBrowsing.matches.length
      },
      virusTotal,
      riskSignals: Array.isArray(virusTotal.riskSignals) ? virusTotal.riskSignals : []
    });
  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({
      error: "Server error",
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
