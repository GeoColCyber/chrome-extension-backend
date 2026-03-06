import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

app.post("/api", async (req, res) => {
  try {

    const response = await fetch("https://api.example.com/data", {
      headers: {
        "Authorization": `Bearer ${process.env.API_KEY}`
      }
    });

    const data = await response.json();
    res.json(data);

  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running");
});
