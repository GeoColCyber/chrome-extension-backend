import express from "express";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

// Optional health check
app.get("/", (req, res) => {
  res.json({ ok: true, service: "guardis-backend" });
});

app.post("/api", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({ error: "Missing API_KEY environment variable" });
    }

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
        reason: "non_http_url"
      });
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

    const googleResponse = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(requestBody)
      }
    );

    const rawText = await googleResponse.text();

    if (!googleResponse.ok) {
      return res.status(502).json({
        error: "Google Safe Browsing request failed",
        status: googleResponse.status,
        details: rawText
      });
    }

    let data = {};
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch {
      return res.status(502).json({
        error: "Invalid JSON returned by Google Safe Browsing",
        details: rawText
      });
    }

    const matches = Array.isArray(data.matches) ? data.matches : [];
    const threatTypes = [...new Set(matches.map((m) => m.threatType).filter(Boolean))];

    return res.json({
      safe: matches.length === 0,
      matches,
      threatTypes
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
