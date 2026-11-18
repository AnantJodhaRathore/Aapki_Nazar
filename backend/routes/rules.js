const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/", (req, res) => {
  try {
    const rulesPath = path.join(__dirname, "../config/detection_rules.json");
    const rulesData = fs.readFileSync(rulesPath, "utf-8");
    const rules = JSON.parse(rulesData);
    res.json(rules);
  } catch (err) {
    console.error("Failed to read detection_rules.json:", err);
    res.status(500).json({ error: "Failed to load rules catalog" });
  }
});

module.exports = router;
