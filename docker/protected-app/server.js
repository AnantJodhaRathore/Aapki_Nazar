const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 3000;

const SAMPLE_PRODUCTS = [
  { id: 101, name: "Enterprise SOC Gateway License", category: "software", price: 499 },
  { id: 102, name: "Autonomous WAF Defense Sensor", category: "security", price: 299 },
  { id: 103, name: "Zero-Trust Threat Telemetry Agent", category: "security", price: 199 },
  { id: 104, name: "Next-Gen Firewall Appliance", category: "hardware", price: 1299 },
  { id: 105, name: "SIEM Cloud Log Ingestion Pipe", category: "cloud", price: 349 }
];

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // Helper response sender
  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, {
      "Content-Type": "application/json",
      "X-Protected-By": "OWASP-CRS-ModSecurity",
      "X-Backend-Server": "Aapki-Nazar-Protected-App/1.0"
    });
    res.end(JSON.stringify(data, null, 2));
  };

  // Collect request body if POST/PUT
  let bodyData = "";
  req.on("data", chunk => {
    bodyData += chunk;
    if (bodyData.length > 1e6) {
      req.socket.destroy();
    }
  });

  req.on("end", () => {
    let jsonBody = {};
    if (bodyData) {
      try {
        jsonBody = JSON.parse(bodyData);
      } catch (e) {
        // Form urlencoded or raw text
        jsonBody = { raw: bodyData };
      }
    }

    console.log(`[PROTECTED-APP] ${new Date().toISOString()} ${method} ${pathname} from ${req.socket.remoteAddress}`);

    // Routes
    if (pathname === "/" && method === "GET") {
      return sendJson(200, {
        status: "online",
        application: "Aapki Nazar Protected Demo Store",
        version: "1.0.0",
        message: "Request successfully passed through OWASP Core Rule Set gateway.",
        endpoints: [
          "GET /health",
          "GET /products?search=term",
          "POST /login",
          "POST /feedback"
        ]
      });
    }

    if (pathname === "/health" && method === "GET") {
      return sendJson(200, {
        status: "healthy",
        uptimeSeconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
      });
    }

    if (pathname === "/products" && method === "GET") {
      const query = (parsedUrl.query.search || "").toLowerCase().trim();
      let filtered = SAMPLE_PRODUCTS;
      if (query) {
        filtered = SAMPLE_PRODUCTS.filter(p =>
          p.name.toLowerCase().includes(query) ||
          p.category.toLowerCase().includes(query)
        );
      }
      return sendJson(200, {
        query: parsedUrl.query.search || null,
        count: filtered.length,
        products: filtered
      });
    }

    if (pathname === "/login" && method === "POST") {
      const username = jsonBody.username || "";
      const password = jsonBody.password || "";

      if (!username || !password) {
        return sendJson(400, {
          success: false,
          error: "Username and password required"
        });
      }

      // Safe benign dummy authentication check
      if (username === "demo" && password === "demo123") {
        return sendJson(200, {
          success: true,
          token: "demo-jwt-sample-token-12345",
          message: "Benign login successful."
        });
      }

      return sendJson(401, {
        success: false,
        message: "Invalid credentials. (Hint: demo / demo123)"
      });
    }

    if (pathname === "/feedback" && method === "POST") {
      return sendJson(200, {
        success: true,
        message: "Feedback submitted successfully.",
        received: {
          name: jsonBody.name || "Anonymous",
          messageLength: (jsonBody.message || "").length
        }
      });
    }

    // 404 for unknown endpoints
    return sendJson(404, {
      error: "Not Found",
      path: pathname
    });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[PROTECTED-APP] Aapki Nazar Protected Demo Service running on port ${PORT}`);
});

