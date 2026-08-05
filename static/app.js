let allFindings = [];
let pieChart = null;
let barChart = null;
let activeFilter = 'all';

async function runScan() {
  const url = document.getElementById('repoUrl').value.trim();
  if (!url) return;
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  const status = document.getElementById('statusText');
  btn.disabled = true;
  spinner.style.display = 'block';
  status.textContent = 'Cloning and scanning repository...';
  document.getElementById('findingsPanel').style.display = 'block';
  document.getElementById('loadingOverlay').style.display = 'flex';
  document.getElementById('statsRow').style.display = 'none';
  document.getElementById('chartsRow').style.display = 'none';
  document.getElementById('findingsBody').innerHTML = '';
  document.getElementById('emptyState').style.display = 'none';
  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({repo_url: url})
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed');
    allFindings = data.findings || [];
    renderStats(allFindings);
    renderCharts(allFindings);
    renderFindings(allFindings);
    renderRemediations(allFindings);
    status.textContent = 'Scan complete — ' + allFindings.length + ' findings for ' + url;
    await loadHistory();
  } catch(e) {
    status.textContent = e.message;
    document.getElementById('emptyState').style.display = 'block';
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
    document.getElementById('loadingOverlay').style.display = 'none';
  }
}

function renderStats(findings) {
  const high = findings.filter(f => f.severity && f.severity.toLowerCase() === 'high').length;
  const med = findings.filter(f => f.severity && f.severity.toLowerCase() === 'medium').length;
  const low = findings.filter(f => f.severity && f.severity.toLowerCase() === 'low').length;
  document.getElementById('statTotal').textContent = findings.length;
  document.getElementById('statHigh').textContent = high;
  document.getElementById('statMed').textContent = med;
  document.getElementById('statLow').textContent = low;
  document.getElementById('statsRow').style.display = 'grid';
}

function renderCharts(findings) {
  const high = findings.filter(f => f.severity && f.severity.toLowerCase() === 'high').length;
  const med = findings.filter(f => f.severity && f.severity.toLowerCase() === 'medium').length;
  const low = findings.filter(f => f.severity && f.severity.toLowerCase() === 'low').length;
  if (pieChart) pieChart.destroy();
  pieChart = new Chart(document.getElementById('pieChart'), {
    type: 'doughnut',
    data: {
      labels: ['High', 'Medium', 'Low'],
      datasets: [{data: [high, med, low], backgroundColor: ['#ef4444','#f59e0b','#22c55e'], borderWidth: 0, hoverOffset: 4}]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {legend: {position: 'right', labels: {color:'#94a3b8', font:{size:12}, padding:12, boxWidth:12, borderRadius:4}}}
    }
  });
  const checkCounts = {};
  findings.forEach(f => {
    const name = (f.check_name || 'Unknown').replace('Missing ', '').replace(' Risk', '').replace(' Enabled', '');
    checkCounts[name] = (checkCounts[name] || 0) + 1;
  });
  const sorted = Object.entries(checkCounts).sort((a,b) => b[1]-a[1]).slice(0,8);
  if (barChart) barChart.destroy();
  barChart = new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: sorted.map(e => e[0]),
      datasets: [{data: sorted.map(e => e[1]), backgroundColor: '#3b82f6', borderRadius: 4, hoverBackgroundColor: '#60a5fa'}]
    },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      plugins: {legend: {display: false}},
      scales: {
        x: {grid:{color:'#1e293b'}, ticks:{color:'#64748b', font:{size:11}}},
        y: {grid:{display:false}, ticks:{color:'#94a3b8', font:{size:11}}}
      }
    }
  });
  document.getElementById('chartsRow').style.display = 'grid';
}

function filterFindings(filter, btn) {
  activeFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => { b.className = 'filter-btn'; });
  if (filter === 'all') btn.className = 'filter-btn active';
  else btn.className = 'filter-btn active-' + filter;
  const filtered = filter === 'all' ? allFindings : allFindings.filter(f => f.severity && f.severity.toLowerCase() === filter);
  renderFindings(filtered);
}

function renderFindings(findings) {
  const tbody = document.getElementById('findingsBody');
  const empty = document.getElementById('emptyState');
  const count = document.getElementById('findingsCount');
  count.textContent = findings.length;
  if (!findings.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  tbody.innerHTML = findings.map(f => {
    const sev = (f.severity || 'low').toLowerCase();
    const sevClass = sev === 'high' ? 'sev-high' : sev === 'medium' ? 'sev-medium' : 'sev-low';
    const file = (f.file_path || '-').split('/').pop();
    return `<tr>
      <td><span class="sev ${sevClass}">${(f.severity||'LOW').toUpperCase()}</span></td>
      <td><span class="check-name">${f.check_name || '-'}</span></td>
      <td><span class="filepath" title="${f.file_path || ''}">${file}</span></td>
      <td><span class="linenum">${f.line_number || '-'}</span></td>
      <td><span class="detail-text">${f.detail || '-'}</span></td>
    </tr>`;
  }).join('');
}

const REMEDIATIONS = {
  "Hardcoded Secret": {sev:"high", fix:"Move the value to a .env file and load it with os.getenv(). Never commit credentials to version control.", code:"# Bad\nAPI_KEY = 'sk-abc123'\n\n# Good\nimport os\nfrom dotenv import load_dotenv\nload_dotenv()\nAPI_KEY = os.getenv('API_KEY')"},
  "SQL Injection Risk": {sev:"high", fix:"Use parameterised queries. Pass values as a tuple to cursor.execute() — never format them into the query string.", code:"# Bad\ncursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n\n# Good\ncursor.execute('SELECT * FROM users WHERE name = ?', (name,))"},
  "Missing Authentication": {sev:"high", fix:"Add a Depends() call to the route function signature referencing your authentication dependency.", code:"from fastapi import Depends\n\n@app.get('/secure')\ndef secure_route(user = Depends(get_current_user)):\n    return {'ok': True}"},
  "Debug Mode Enabled": {sev:"med", fix:"Set debug=False in production. Use an environment variable to control this — never hardcode True.", code:"import os\nDEBUG = os.getenv('DEBUG', 'false').lower() == 'true'\napp.run(debug=DEBUG)"},
  "Missing Input Validation": {sev:"med", fix:"Add type hints to all function parameters. In FastAPI, use Pydantic models to validate request bodies.", code:"from pydantic import BaseModel\n\nclass ScanRequest(BaseModel):\n    repo_url: str\n\n@app.post('/scan')\ndef scan(payload: ScanRequest):\n    ..."},
  "Sensitive Data in Response": {sev:"high", fix:"Never return password, token, or secret fields in API responses. Use a response schema that explicitly excludes sensitive fields.", code:"class UserResponse(BaseModel):\n    id: int\n    email: str\n    # password field deliberately excluded"},
  "Stack Trace Exposure": {sev:"med", fix:"Catch exceptions and return a generic error message. Log the full exception server-side only.", code:"# Bad\nexcept Exception as e:\n    return {'error': str(e)}\n\n# Good\nexcept Exception as e:\n    logger.exception(e)\n    raise HTTPException(status_code=500, detail='Internal server error')"},
  "Environment Variable in Source": {sev:"high", fix:"Remove the hardcoded value, add it to a .env file, and load it with os.getenv().", code:"# .env\nSECRET_KEY=your-secret-here\n\n# Python\nimport os\nSECRET_KEY = os.getenv('SECRET_KEY')"},
  "Missing Rate Limiting": {sev:"med", fix:"Add rate limiting using slowapi. Login, register, and password reset endpoints need this most urgently.", code:"from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/login')\n@limiter.limit('5/minute')\ndef login(request: Request): ..."},
  "Missing Security Headers": {sev:"med", fix:"Set X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, and Strict-Transport-Security on all responses.", code:"@app.middleware('http')\nasync def add_security_headers(request, call_next):\n    response = await call_next(request)\n    response.headers['X-Frame-Options'] = 'DENY'\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    return response"},
  "Exposed Admin Endpoint": {sev:"high", fix:"Add authentication to all admin and debug routes. Remove debug endpoints entirely in production.", code:"@app.get('/admin')\ndef admin(user = Depends(require_admin)):\n    ..."},
  "IDOR Risk": {sev:"high", fix:"After fetching a record by ID, verify the current user owns it before returning it.", code:"record = db.get_record(record_id)\nif record.owner_id != current_user.id:\n    raise HTTPException(status_code=403, detail='Forbidden')"},
  "Missing File Upload Validation": {sev:"high", fix:"Check file extension against an allowlist, validate the content-type header, and enforce a maximum file size.", code:"ALLOWED = {'.jpg', '.png', '.pdf'}\nMAX_SIZE = 5 * 1024 * 1024\n\next = os.path.splitext(file.filename)[1].lower()\nif ext not in ALLOWED:\n    raise HTTPException(400, 'File type not allowed')"},
  "Row Level Security Missing": {sev:"high", fix:"Filter all database queries by the current user's ID.", code:"# Bad\nrows = db.execute('SELECT * FROM orders').fetchall()\n\n# Good\nrows = db.execute('SELECT * FROM orders WHERE user_id = ?', (current_user.id,)).fetchall()"},
  "Missing HTTPS Enforcement": {sev:"high", fix:"Add an HTTPS redirect middleware to your FastAPI application.", code:"from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\napp.add_middleware(HTTPSRedirectMiddleware)"},
  "Missing 2FA": {sev:"med", fix:"Implement TOTP-based 2FA using pyotp. Require a one-time code at login in addition to the password.", code:"import pyotp\n\ntotp = pyotp.TOTP(user.totp_secret)\nif not totp.verify(otp_code):\n    raise HTTPException(401, 'Invalid OTP')"},
  "Missing Server Side Validation": {sev:"med", fix:"Validate all incoming data on the server regardless of client-side validation.", code:"from pydantic import BaseModel, validator\n\nclass CreateUser(BaseModel):\n    age: int\n\n    @validator('age')\n    def age_must_be_positive(cls, v):\n        if v < 0:\n            raise ValueError('Age must be positive')\n        return v"},
  "Outdated Dependency": {sev:"med", fix:"Update the package to the latest stable version and test for breaking changes.", code:"pip install --upgrade flask\npip freeze > requirements.txt"},
  "API Key Exposed on Frontend": {sev:"high", fix:"Never put API keys in frontend code. Move all API calls to your backend.", code:"// Bad\nconst apiKey = 'sk-abc123';\n\n// Good — call your own backend\nconst res = await fetch('/api/data');"},
  "Insecure Token Storage": {sev:"high", fix:"Store authentication tokens in httpOnly cookies, not localStorage. httpOnly cookies cannot be accessed by JavaScript.", code:"// Bad\nlocalStorage.setItem('token', token);\n\n// Good — server sets httpOnly cookie\nresponse.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')"},
};

function renderRemediations(findings) {
  const panel = document.getElementById('remediationPanel');
  const list = document.getElementById('remediationList');
  const seen = new Set();
  const items = [];
  findings.forEach(f => {
    const name = f.check_name;
    if (!seen.has(name) && REMEDIATIONS[name]) {
      seen.add(name);
      items.push({name, sev: (f.severity||'').toLowerCase(), ...REMEDIATIONS[name]});
    }
  });
  if (!items.length) { panel.style.display = 'none'; return; }
  list.innerHTML = items.map(item => {
    const borderClass = item.sev === 'high' ? 'high-border' : item.sev === 'medium' ? 'med-border' : '';
    const sevCol = item.sev === 'high' ? 'var(--high)' : item.sev === 'medium' ? 'var(--med)' : 'var(--low)';
    return `<div class="remediation-item ${borderClass}">
      <div class="remediation-check">
        <span style="color:${sevCol};font-size:11px;font-weight:700;text-transform:uppercase;margin-right:6px">${item.sev}</span>${item.name}
      </div>
      <div class="remediation-text">${item.fix}</div>
      ${item.code ? `<code class="remediation-code">${item.code}</code>` : ''}
    </div>`;
  }).join('');
  panel.style.display = 'block';
}

async function loadHistory() {
  const list = document.getElementById('historyList');
  try {
    const res = await fetch('/scans');
    const scans = await res.json();
    if (!Array.isArray(scans) || !scans.length) { list.innerHTML = '<div class="empty">No previous scans.</div>'; return; }
    list.innerHTML = scans.map(s => `
      <div class="history-item" onclick="loadScanFindings(${s.id})">
        <div>
          <div class="history-url">${s.repo_url}</div>
          <div class="history-meta">${new Date(s.timestamp).toLocaleString()}</div>
        </div>
        <span class="history-badge">${s.total_findings} findings</span>
      </div>
    `).join('');
  } catch(e) { list.innerHTML = '<div class="empty">Unable to load history.</div>'; }
}

async function loadScanFindings(id) {
  try {
    const res = await fetch('/scans/' + id);
    const findings = await res.json();
    allFindings = findings;
    document.getElementById('findingsPanel').style.display = 'block';
    renderStats(findings);
    renderCharts(findings);
    renderFindings(findings);
    renderRemediations(findings);
    document.getElementById('statusText').textContent = 'Showing findings for scan ' + id;
  } catch(e) { document.getElementById('statusText').textContent = 'Unable to load findings.'; }
}

loadHistory();
document.getElementById('repoUrl').addEventListener('keydown', e => { if (e.key === 'Enter') runScan(); });
