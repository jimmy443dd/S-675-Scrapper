const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { VulnerabilityScanner, TokenManager, ReportGenerator } = require('./advanced-pentest-suite');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

let scanStatus = {
  isRunning: false,
  progress: 0,
  currentTask: '',
  results: null,
};

// Dashboard HTML
app.get('/', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Advanced Penetration Testing Suite</title>
      <style>
        body { font-family: Arial; margin: 40px; background: #1e1e1e; color: #fff; }
        .container { max-width: 800px; margin: 0 auto; }
        button { padding: 10px 20px; font-size: 16px; background: #ff6b6b; color: white; border: none; cursor: pointer; }
        button:hover { background: #ff5252; }
        .status { margin: 20px 0; padding:  20px; background: #333; border-radius: 5px; }
        .results { margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border:  1px solid #555; padding: 10px; text-align: left; }
        th { background: #444; }
        .critical { color: #ff6b6b; }
        . high { color: #ffa500; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔓 Advanced Penetration Testing Suite</h1>
        
        <div class="status">
          <h3>Target Domain</h3>
          <input type="text" id="targetDomain" value="https://www.serve.com" style="width: 100%; padding: 10px; color: black;">
          <button onclick="startScan()">▶ Start Scan</button>
          <button onclick="getStatus()">🔄 Check Status</button>
          <button onclick="downloadReport()">📥 Download Report</button>
        </div>

        <div id="statusDiv" class="status" style="display: none;">
          <h3>Scan Status</h3>
          <p>Progress: <span id="progress">0</span>%</p>
          <p>Current Task: <span id="currentTask">-</span></p>
        </div>

        <div id="resultsDiv" class="results" style="display:none;">
          <h3>Results</h3>
          <h4>Extracted Emails</h4>
          <div id="emailsList"></div>
          
          <h4>Vulnerabilities</h4>
          <div id="vulnerabilitiesList"></div>
        </div>
      </div>

      <script>
        async function startScan() {
          const domain = document.getElementById('targetDomain').value;
          const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
          });
          const data = await response.json();
          document.getElementById('statusDiv').style.display = 'block';
          pollStatus();
        }

        async function getStatus() {
          const response = await fetch('/status');
          const data = await response.json();
          document.getElementById('progress').textContent = data.progress;
          document.getElementById('currentTask').textContent = data.currentTask;
          
          if (data.results) {
            displayResults(data.results);
          }
        }

        async function pollStatus() {
          setInterval(getStatus, 2000);
        }

        function displayResults(results) {
          document.getElementById('resultsDiv').style.display = 'block';
          
          const emailsList = document.getElementById('emailsList');
          emailsList.innerHTML = '<ul>' + results.extractedEmails. map(e => `<li>${e}</li>`).join('') + '</ul>';
          
          const vulnList = document.getElementById('vulnerabilitiesList');
          vulnList.innerHTML = '<table><tr><th>Type</th><th>Severity</th><th>Endpoint</th></tr>' +
            results.findings.map(f => `<tr><td>${f.type}</td><td class="${f.severity. toLowerCase()}">${f.severity}</td><td>${f.endpoint || '-'}</td></tr>`).join('') +
            '</table>';
        }

        function downloadReport() {
          window.location.href = '/download-report';
        }
      </script>
    </body>
    </html>
  `;
  res.send(html);
});

// API:  Start scan
app.post('/scan', async (req, res) => {
  const { domain } = req.body;

  if (scanStatus.isRunning) {
    return res.status(400).json({ error: 'Scan already running' });
  }

  scanStatus.isRunning = true;
  scanStatus.progress = 0;

  // Run scan asynchronously
  (async () => {
    try {
      const tokenManager = new TokenManager();
      scanStatus.currentTask = 'Obtaining authentication tokens... ';
      await tokenManager.obtainTokens(domain);

      const scanner = new VulnerabilityScanner(domain, tokenManager);
      scanStatus.currentTask = 'Running vulnerability tests...';
      const results = await scanner.runAllTests();

      scanStatus.results = results;
      scanStatus. progress = 100;
      scanStatus.currentTask = 'Scan complete!';
    } catch (err) {
      scanStatus.currentTask = `Error: ${err.message}`;
    } finally {
      scanStatus. isRunning = false;
    }
  })();

  res.json({ message: 'Scan started', scanId: Date.now() });
});

// API: Get status
app.get('/status', (req, res) => {
  res.json(scanStatus);
});

// API: Download report
app.get('/download-report', (req, res) => {
  const reportDir = './reports';
  const files = fs.readdirSync(reportDir).filter(f => f.endsWith('.json'));
  const latestReport = files. sort().pop();

  if (!latestReport) {
    return res.status(404).json({ error: 'No reports found' });
  }

  res.download(path.join(reportDir, latestReport));
});

app.listen(PORT, () => {
  console.log(`[+] Penetration Testing Suite running on http://localhost:${PORT}`);
});
