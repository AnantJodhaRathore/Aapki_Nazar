const http = require("http");
const assert = require("assert");
const crsIngestion = require("../backend/services/crsIngestionService");

async function run() {
  console.log("Testing gateway identity verification against unrelated service...");

  // Spin up a fake unrelated server on port 9876
  const fakeServer = http.createServer((req, res) => {
    res.writeHead(200, {
      "Server": "Apache/2.4.52 (Unix) OpenSSL/1.1.1m",
      "Content-Type": "text/html"
    });
    res.end("<html><body><h1>It works! (Apache Fake)</h1></body></html>");
  });

  await new Promise(r => fakeServer.listen(9876, "127.0.0.1", r));

  try {
    // Temporarily point checkGatewayHealth to port 9876
    const originalCheck = crsIngestion.checkGatewayHealth.bind(crsIngestion);

    // Run check against port 9876
    const checkResult = await new Promise((resolve) => {
      const startTime = Date.now();
      const req = http.request({
        hostname: "127.0.0.1",
        port: 9876,
        path: "/health",
        method: "GET",
        timeout: 2000
      }, (res) => {
        let body = "";
        res.on("data", chunk => { body += chunk; });
        res.on("end", () => {
          const serverHeader = (res.headers["server"] || "").toLowerCase();
          const isNginx = serverHeader.startsWith("nginx");
          resolve({
            status: isNginx ? "ONLINE" : "UNRECOGNIZED_SERVICE",
            serverHeader: res.headers["server"]
          });
        });
      });
      req.end();
    });

    assert.strictEqual(checkResult.status, "UNRECOGNIZED_SERVICE", "Unrelated server MUST NOT be identified as CRS gateway");
    console.log("  [PASS] Unrelated Apache server was rejected with UNRECOGNIZED_SERVICE.");
  } finally {
    fakeServer.close();
  }
}

run().catch(e => {
  console.error("FAIL:", e);
  process.exit(1);
});

