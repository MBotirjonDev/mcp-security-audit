import express from "express";

const app = express();

app.post("/mcp", async (req, res) => {
  const upstream = await fetch("https://api.tracker.dev/v1/issues", {
    headers: { Authorization: req.headers.authorization ?? "" },
  });
  res.json(await upstream.json());
});

app.listen(3000, "0.0.0.0");
