from http.server import HTTPServer, BaseHTTPRequestHandler

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION ENGINE
# Uses simple if statements — no machine learning, no external services.
# Each rule checks for a keyword or pattern and returns a (result, reason) pair.
# ─────────────────────────────────────────────────────────────────────────────

# -- Rule set 1: PHISHING keywords and patterns -------------------------------
# These are strong signals that something is definitely malicious.
PHISHING_KEYWORDS = [
    "verify-account",       # fake account verification pages
    "verify ssn",           # asking for Social Security Number
    "fakesite.com",         # obviously fake domain
    "irs-refund",           # fake IRS / government refund scam
    "suspended. click",     # "your account is suspended, click here"
    "nflx-alert",           # impersonating Netflix
    "amaz0n",               # Amazon with a zero instead of 'o'
    "paypa1",               # PayPal with a '1' instead of 'l'
    "prize-hub",            # fake prize / lottery scam
    "account will be closed",  # threat to close your account
    "secure-dropbox-files", # fake Dropbox link
]

# -- Rule set 2: SUSPICIOUS keywords and patterns ----------------------------
# These are warning signs — not definitely malicious, but worth flagging.
SUSPICIOUS_KEYWORDS = [
    "bit.ly",               # shortened URL — hides the real destination
    "earn $",               # "earn money fast" scam pattern
    "download.exe",         # downloading an executable file is risky
    "click link",           # vague "click this link" with no context
    "guaranteed",           # "guaranteed returns" is a red flag
    "300%",                 # unrealistic percentage return promise
    "update delivery",      # fake parcel delivery scam
    "unknown-cdn",          # unknown content delivery network
    "unsubscribe from all", # suspicious mass unsubscribe email
]


def detect(content):
    """
    Analyse a piece of content (URL, message, or email text).
    Returns: (result, reason)
      - result is "Phishing", "Suspicious", or "Safe"
      - reason is a plain-English explanation shown in the dashboard
    """

    # Convert to lowercase so the check is case-insensitive
    text = content.lower()

    # ── Step 1: Check every phishing keyword ────────────────────────────────
    # If ANY phishing keyword is found, flag it immediately as Phishing.
    for keyword in PHISHING_KEYWORDS:
        if keyword in text:
            return ("Phishing", f'Contains phishing indicator: "{keyword}"')

    # ── Step 2: Check every suspicious keyword ──────────────────────────────
    # Only reached if no phishing keyword matched above.
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            return ("Suspicious", f'Contains suspicious pattern: "{keyword}"')

    # ── Step 3: Default — nothing bad was found ─────────────────────────────
    return ("Safe", "No known threats detected")


# ─────────────────────────────────────────────────────────────────────────────
# 20 FAKE RECORDS
# The 'result' column is now filled automatically by detect() below.
# Each record: (time, username, type, content)
# ─────────────────────────────────────────────────────────────────────────────
RAW_RECORDS = [
    ("09:01", "alice",   "URL",     "https://mybank-secure-login.fakesite.com"),
    ("09:04", "bob",     "Email",   "Your PayPal account is suspended. Click here now."),
    ("09:07", "carol",   "Message", "FREE iPhone 15 winner! Claim at prize-hub.net"),
    ("09:12", "dave",    "URL",     "http://amaz0n-deals.shop/verify-account"),
    ("09:15", "emma",    "Email",   "IRS refund pending — verify SSN at irs-refund.co"),
    ("09:20", "frank",   "Message", "Urgent: your Netflix password was changed. Login: nflx-alert.info"),
    ("09:25", "grace",   "URL",     "http://secure-dropbox-files.xyz/shared-doc"),
    ("09:30", "henry",   "Email",   "Dear user, your Microsoft account will be closed in 24h."),

    ("09:33", "isla",    "URL",     "http://bit.ly/3xFkQ9p"),
    ("09:38", "jack",    "Message", "Hey! Check this out: earn $500/day from home."),
    ("09:41", "karen",   "Email",   "Unsubscribe from all marketing lists — click link."),
    ("09:45", "leo",     "URL",     "https://unknown-cdn-files.net/download.exe"),
    ("09:50", "mia",     "Message", "Your parcel is on hold. Update delivery info here."),
    ("09:55", "noah",    "Email",   "Investment opportunity — 300% returns guaranteed."),
    ("10:01", "olivia",  "URL",     "https://login.paypa1-support.com/help"),

    ("10:05", "peter",   "URL",     "https://www.google.com/search?q=python+tutorial"),
    ("10:08", "quinn",   "Email",   "Meeting reminder: standup at 10 AM tomorrow."),
    ("10:12", "rachel",  "Message", "Can you review my pull request when you get a chance?"),
    ("10:16", "sam",     "URL",     "https://github.com/openai/openai-python"),
    ("10:20", "tina",    "Email",   "Your order #48291 has been shipped. Track it here."),
]

# Run every record through the detection engine and attach result + reason
# Result: (time, username, type, content, result, reason)
RECORDS = []
for (t, u, rtype, content) in RAW_RECORDS:
    result, reason = detect(content)
    RECORDS.append((t, u, rtype, content, result, reason))

# Count totals from actual detection results (drives the stat cards)
TOTAL_SAFE       = sum(1 for r in RECORDS if r[4] == "Safe")
TOTAL_PHISHING   = sum(1 for r in RECORDS if r[4] == "Phishing")
TOTAL_SUSPICIOUS = sum(1 for r in RECORDS if r[4] == "Suspicious")

# ─────────────────────────────────────────────────────────────────────────────
# CHART DATA
# Count records by (result, type) so the charts know how many bars to draw.
# All three charts read from these six simple counters.
# ─────────────────────────────────────────────────────────────────────────────

# Chart 1 — Overview: how many of each type (URL/Message/Email) per result
# This lets us see at a glance which channel is most targeted.
def count(result, rtype):
    return sum(1 for r in RECORDS if r[4] == result and r[2] == rtype)

# Safe counts per type
C1_SAFE_URL  = count("Safe",       "URL")
C1_SAFE_MSG  = count("Safe",       "Message")
C1_SAFE_EML  = count("Safe",       "Email")

# Suspicious counts per type
C1_SUS_URL   = count("Suspicious", "URL")
C1_SUS_MSG   = count("Suspicious", "Message")
C1_SUS_EML   = count("Suspicious", "Email")

# Phishing counts per type
C1_PHI_URL   = count("Phishing",   "URL")
C1_PHI_MSG   = count("Phishing",   "Message")
C1_PHI_EML   = count("Phishing",   "Email")

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY ALERTS
# Build one alert entry per flagged (non-safe) record.
# Each alert shows: username, type, content snippet, number of times that
# exact content was seen, risk level, and the detection reason.
#
# How risk level is assigned:
#   - "Phishing" result  → risk = "High"   (strong indicators found)
#   - "Suspicious" result → risk = "Medium" (warning signs found)
#
# NOTE: These alerts do NOT prove a cyber attack has happened.
# They are based on pattern matching only — a human should review them.
# ─────────────────────────────────────────────────────────────────────────────

# Step 1: Count how many times each (username, content) pair appears in records
from collections import Counter
send_counts = Counter((r[1], r[3]) for r in RECORDS)   # key = (username, content)

# Step 2: Build the ALERTS list — one entry per flagged record
# Each alert: (username, type, content, sent_count, risk, reason)
ALERTS = []
for (time, user, rtype, content, result, reason) in RECORDS:
    # Only include Phishing and Suspicious — skip Safe records
    if result == "Safe":
        continue

    # Assign a simple risk label based on the detection result
    if result == "Phishing":
        risk = "High"       # Phishing = High risk
    else:
        risk = "Medium"     # Suspicious = Medium risk

    # How many times was this exact content sent by this user?
    sent = send_counts[(user, content)]

    ALERTS.append((user, rtype, content, sent, risk, reason))


# ─────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATE
# {SAFE_COUNT}, {PHISH_COUNT}, {SUS_COUNT} are filled from live detection counts
# {TABLE_ROWS} is filled by build_table_rows()
# ─────────────────────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>PhishShield</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #e6edf3;
      min-height: 100vh;
      padding: 40px 20px;
    }}

    header {{
      text-align: center;
      margin-bottom: 48px;
    }}

    header h1 {{
      font-size: 2.4rem;
      font-weight: 700;
      color: #58a6ff;
      letter-spacing: 1px;
    }}

    header p {{
      margin-top: 10px;
      font-size: 1rem;
      color: #8b949e;
      max-width: 520px;
      margin-left: auto;
      margin-right: auto;
      line-height: 1.6;
    }}

    .badge {{
      display: inline-block;
      margin-top: 14px;
      background: #1f2d3d;
      border: 1px solid #30363d;
      color: #3fb950;
      font-size: 0.78rem;
      padding: 4px 12px;
      border-radius: 20px;
      letter-spacing: 0.5px;
    }}

    /* ── stat cards ── */
    .cards {{
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 24px;
      max-width: 900px;
      margin: 0 auto 48px auto;
    }}

    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 32px 28px;
      flex: 1 1 220px;
      max-width: 260px;
      text-align: center;
      transition: border-color 0.2s;
    }}

    .card:hover {{ border-color: #58a6ff; }}

    .card .icon  {{ font-size: 2rem; margin-bottom: 14px; }}
    .card .count {{ font-size: 2.8rem; font-weight: 700; margin-bottom: 6px; }}
    .card .label {{ font-size: 0.88rem; color: #8b949e; line-height: 1.5; }}

    .card.safe  .count {{ color: #3fb950; }}
    .card.phish .count {{ color: #f85149; }}
    .card.sus   .count {{ color: #d29922; }}

    /* ── section heading ── */
    .section-header {{
      max-width: 960px;
      margin: 0 auto 16px auto;
      padding: 0 4px;
    }}

    .section-header h2 {{
      font-size: 1.1rem;
      font-weight: 600;
      color: #c9d1d9;
    }}

    /* ── records table ── */
    .table-wrap {{
      max-width: 960px;
      margin: 0 auto 48px auto;
      overflow-x: auto;
      border: 1px solid #30363d;
      border-radius: 12px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}

    thead th {{
      background: #161b22;
      color: #8b949e;
      font-weight: 600;
      text-align: left;
      padding: 12px 16px;
      border-bottom: 1px solid #30363d;
      white-space: nowrap;
    }}

    tbody tr {{
      border-bottom: 1px solid #21262d;
      transition: background 0.15s;
    }}

    tbody tr:last-child {{ border-bottom: none; }}
    tbody tr:hover {{ background: #1c2128; }}

    tbody td {{
      padding: 11px 16px;
      vertical-align: middle;
    }}

    .type-pill {{
      display: inline-block;
      padding: 2px 9px;
      border-radius: 20px;
      font-size: 0.78rem;
      font-weight: 600;
    }}

    .type-url     {{ background: #1f3a5f; color: #79c0ff; }}
    .type-message {{ background: #3b2a4a; color: #d2a8ff; }}
    .type-email   {{ background: #1e3a2f; color: #56d364; }}

    .result-pill {{
      display: inline-block;
      padding: 3px 11px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 700;
    }}

    .result-safe       {{ background: #1a3a22; color: #3fb950; }}
    .result-suspicious {{ background: #3d2f00; color: #d29922; }}
    .result-phishing   {{ background: #3d1a1a; color: #f85149; }}

    /* ── warning reason box ── */
    .reason {{
      font-size: 0.8rem;
      padding: 4px 10px;
      border-radius: 6px;
      display: inline-block;
      max-width: 260px;
      line-height: 1.4;
    }}

    .reason-safe       {{ color: #57606a; }}
    .reason-suspicious {{ color: #d29922; background: #2a1f00; }}
    .reason-phishing   {{ color: #f85149; background: #2a0f0f; }}

    .content-cell {{
      max-width: 280px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      color: #c9d1d9;
    }}

    .time-cell {{ color: #8b949e; white-space: nowrap; }}
    .user-cell {{ font-weight: 600; color: #e6edf3; }}

    /* ── security alerts ── */
    .alert-disclaimer {{
      margin-bottom: 20px;
      padding: 14px 18px;
      border-radius: 8px;
      background: #161b22;
      border-left: 4px solid #58a6ff;
      font-size: 0.85rem;
      color: #8b949e;
      line-height: 1.6;
    }}

    .alert-disclaimer strong {{
      color: #c9d1d9;
    }}

    /* ── toggle button for the alerts panel ── */
    .alerts-toggle {{
      max-width: 960px;
      margin: 0 auto 16px auto;
      padding: 0 4px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }}

    .alerts-toggle h2 {{
      font-size: 1.1rem;
      font-weight: 600;
      color: #c9d1d9;
    }}

    .btn-toggle {{
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 6px 16px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
    }}

    .btn-toggle:hover {{
      background: #30363d;
      color: #e6edf3;
    }}

    /* the alerts panel — hidden by default, shown when JS adds class 'open' */
    .alerts-panel {{
      max-width: 960px;
      margin: 0 auto 48px auto;
      display: none;
    }}

    .alerts-panel.open {{
      display: block;
    }}

    .alert-grid {{
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}

    .alert-row {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 14px 18px;
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      gap: 12px;
    }}

    .alert-row.risk-high   {{ border-left: 4px solid #f85149; }}
    .alert-row.risk-medium {{ border-left: 4px solid #d29922; }}

    .alert-user {{
      font-weight: 700;
      color: #e6edf3;
      min-width: 80px;
    }}

    .alert-meta {{
      flex: 1;
      min-width: 200px;
    }}

    .alert-content {{
      font-size: 0.85rem;
      color: #c9d1d9;
      margin-top: 3px;
      word-break: break-all;
    }}

    .alert-reason {{
      font-size: 0.8rem;
      margin-top: 5px;
      color: #8b949e;
    }}

    .alert-right {{
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 6px;
      min-width: 120px;
    }}

    .risk-pill {{
      display: inline-block;
      padding: 3px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 700;
    }}

    .risk-high   {{ background: #3d1a1a; color: #f85149; }}
    .risk-medium {{ background: #3d2f00; color: #d29922; }}

    .alert-sent {{
      font-size: 0.78rem;
      color: #8b949e;
    }}

    /* ── charts section ── */
    .chart-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 24px;
      max-width: 960px;
      margin: 0 auto 48px auto;
    }}

    .chart-box {{
      flex: 1 1 280px;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 20px 20px 16px 20px;
    }}

    .chart-box h3 {{
      font-size: 0.92rem;
      font-weight: 600;
      color: #c9d1d9;
      margin-bottom: 4px;
    }}

    .chart-desc {{
      font-size: 0.78rem;
      color: #57606a;
      margin-bottom: 16px;
      line-height: 1.4;
    }}

    /* bar chart built from HTML — no SVG library needed */
    .bar-chart {{
      display: flex;
      flex-direction: column;
      gap: 9px;
    }}

    .bar-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.8rem;
    }}

    .bar-label {{
      width: 72px;
      color: #8b949e;
      flex-shrink: 0;
      text-align: right;
    }}

    .bar-track {{
      flex: 1;
      background: #21262d;
      border-radius: 4px;
      height: 18px;
      overflow: hidden;
    }}

    .bar-fill {{
      height: 100%;
      border-radius: 4px;
      min-width: 2px;
    }}

    .bar-val {{
      width: 20px;
      color: #8b949e;
      font-size: 0.78rem;
      flex-shrink: 0;
    }}

    .bar-safe  {{ background: #238636; }}
    .bar-sus   {{ background: #9e6a03; }}
    .bar-phi   {{ background: #b62324; }}
    .bar-url   {{ background: #1f6feb; }}
    .bar-msg   {{ background: #8957e5; }}
    .bar-eml   {{ background: #2ea043; }}

    /* legend dots */
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 14px;
    }}

    .legend-item {{
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.76rem;
      color: #8b949e;
    }}

    .legend-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }}

    /* ── divider / footer ── */
    .divider {{
      max-width: 960px;
      margin: 0 auto 32px auto;
      border: none;
      border-top: 1px solid #21262d;
    }}

    footer {{
      text-align: center;
      font-size: 0.8rem;
      color: #484f58;
    }}
  </style>
</head>
<body>

  <header>
    <h1>&#128737; PhishShield</h1>
    <p>Real-time cybersecurity dashboard that monitors URLs, messages,
       and emails for phishing attempts and suspicious activity.</p>
    <span class="badge">&#9679; System Active</span>
  </header>

  <!-- ── stat cards — counts come from the live detection engine ── -->
  <div class="cards">
    <div class="card safe">
      <div class="icon">&#9989;</div>
      <div class="count">{SAFE_COUNT}</div>
      <div class="label">Safe Detections<br/>URLs &bull; Messages &bull; Emails</div>
    </div>
    <div class="card phish">
      <div class="icon">&#128680;</div>
      <div class="count">{PHISH_COUNT}</div>
      <div class="label">Phishing Detected<br/>URLs &bull; Messages &bull; Emails</div>
    </div>
    <div class="card sus">
      <div class="icon">&#9888;&#65039;</div>
      <div class="count">{SUS_COUNT}</div>
      <div class="label">Suspicious Flagged<br/>URLs &bull; Messages &bull; Emails</div>
    </div>
  </div>

  <!-- ── charts section ── -->
  <div class="section-header">
    <h2>&#128200; Detection Charts</h2>
  </div>

  <div class="chart-row">
    {CHARTS}
  </div>

  <!-- ── records table ── -->
  <div class="section-header">
    <h2>&#128202; Recent Detection Records</h2>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Time</th>
          <th>Username</th>
          <th>Type</th>
          <th>Content</th>
          <th>Result</th>
          <th>Why Flagged</th>
        </tr>
      </thead>
      <tbody>
        {TABLE_ROWS}
      </tbody>
    </table>
  </div>

  <!-- ── security alerts section — shown/hidden by the toggle button ── -->
  <div class="alerts-toggle">
    <h2>&#128274; Security Alerts</h2>
    <button class="btn-toggle" onclick="
      var p = document.getElementById('alertsPanel');
      var open = p.classList.toggle('open');
      this.textContent = open ? '&#9650; Hide Alerts' : '&#128680; Show Alerts';
    ">&#128680; Show Alerts</button>
  </div>

  <div class="alerts-panel" id="alertsPanel">
    <!-- Disclaimer notice -->
    <div class="alert-disclaimer">
      <strong>&#8505;&#65039; Important notice:</strong>
      These alerts are generated by <strong>keyword pattern matching only</strong>.
      A suspicious or phishing flag <strong>does not automatically prove</strong> a cyber attack
      has taken place. It means the content matched a known warning pattern and should be
      <strong>reviewed by a human</strong> before any action is taken.
      False positives are possible.
    </div>

    <!-- One alert row per flagged record -->
    <div class="alert-grid">
      {ALERT_ROWS}
    </div>
  </div>

  <hr class="divider"/>
  <footer>PhishShield &mdash; Cybersecurity Dashboard &mdash; Running on localhost</footer>

</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# BUILD CHARTS
# Three horizontal bar charts, built from plain HTML divs (no libraries).
# Each bar width is a percentage of the chart's maximum value so bars scale
# relative to each other — easy to read at a glance.
# ─────────────────────────────────────────────────────────────────────────────

def make_bar(label, value, max_val, color_class):
    """Return one bar row: label | filled bar | number"""
    # Calculate how wide the bar should be (minimum 2% so zero still shows)
    pct = max(2, int(value / max_val * 100)) if max_val > 0 else 2
    return f"""
      <div class="bar-row">
        <span class="bar-label">{label}</span>
        <div class="bar-track">
          <div class="bar-fill {color_class}" style="width:{pct}%"></div>
        </div>
        <span class="bar-val">{value}</span>
      </div>"""


def build_charts(c1_safe_url, c1_safe_msg, c1_safe_eml,
                 c1_sus_url,  c1_sus_msg,  c1_sus_eml,
                 c1_phi_url,  c1_phi_msg,  c1_phi_eml):
    """
    Build three chart boxes and return them as a single HTML string.

    Chart 1 – Overview (Safe vs Suspicious vs Phishing)
      Compares the three result categories across all content types.
      Helps you see whether your network is mostly safe or heavily targeted.

    Chart 2 – Suspicious Breakdown (URLs / Messages / Emails)
      Shows only suspicious detections split by content type.
      Helps you see WHICH channel (URL, message or email) suspicious
      activity arrives through most often.

    Chart 3 – Phishing Breakdown (URLs / Messages / Emails)
      Shows only phishing detections split by content type.
      Helps you see WHICH channel phishing attacks prefer so you know
      where to focus your defences.
    """

    # ── Chart 1: Safe vs Suspicious vs Phishing totals ───────────────────────
    # One bar per result category — how many detections in total for each
    total_safe = c1_safe_url + c1_safe_msg + c1_safe_eml
    total_sus  = c1_sus_url  + c1_sus_msg  + c1_sus_eml
    total_phi  = c1_phi_url  + c1_phi_msg  + c1_phi_eml
    max1 = max(total_safe, total_sus, total_phi, 1)

    chart1 = f"""
  <div class="chart-box">
    <h3>&#128269; Chart 1 &mdash; Overview</h3>
    <p class="chart-desc">
      Compares total Safe, Suspicious, and Phishing detections across
      all content types. A high Phishing bar means more active attacks.
    </p>
    <div class="bar-chart">
      {make_bar("Safe",       total_safe, max1, "bar-safe")}
      {make_bar("Suspicious", total_sus,  max1, "bar-sus")}
      {make_bar("Phishing",   total_phi,  max1, "bar-phi")}
    </div>
    <div class="legend">
      <span class="legend-item"><span class="legend-dot" style="background:#238636"></span>Safe</span>
      <span class="legend-item"><span class="legend-dot" style="background:#9e6a03"></span>Suspicious</span>
      <span class="legend-item"><span class="legend-dot" style="background:#b62324"></span>Phishing</span>
    </div>
  </div>"""

    # ── Chart 2: Suspicious by type ──────────────────────────────────────────
    # Shows how suspicious detections are split: URLs, Messages, Emails
    max2 = max(c1_sus_url, c1_sus_msg, c1_sus_eml, 1)

    chart2 = f"""
  <div class="chart-box">
    <h3>&#9888;&#65039; Chart 2 &mdash; Suspicious Breakdown</h3>
    <p class="chart-desc">
      Breaks down suspicious detections by content type.
      Shows which channel &mdash; URL, Message, or Email &mdash;
      carries the most suspicious activity.
    </p>
    <div class="bar-chart">
      {make_bar("URLs",     c1_sus_url, max2, "bar-url")}
      {make_bar("Messages", c1_sus_msg, max2, "bar-msg")}
      {make_bar("Emails",   c1_sus_eml, max2, "bar-eml")}
    </div>
    <div class="legend">
      <span class="legend-item"><span class="legend-dot" style="background:#1f6feb"></span>URL</span>
      <span class="legend-item"><span class="legend-dot" style="background:#8957e5"></span>Message</span>
      <span class="legend-item"><span class="legend-dot" style="background:#2ea043"></span>Email</span>
    </div>
  </div>"""

    # ── Chart 3: Phishing by type ─────────────────────────────────────────────
    # Shows how phishing detections are split: URLs, Messages, Emails
    max3 = max(c1_phi_url, c1_phi_msg, c1_phi_eml, 1)

    chart3 = f"""
  <div class="chart-box">
    <h3>&#128680; Chart 3 &mdash; Phishing Breakdown</h3>
    <p class="chart-desc">
      Breaks down phishing detections by content type.
      Shows which channel phishing attacks arrive through most,
      so you know where to strengthen your defences.
    </p>
    <div class="bar-chart">
      {make_bar("URLs",     c1_phi_url, max3, "bar-url")}
      {make_bar("Messages", c1_phi_msg, max3, "bar-msg")}
      {make_bar("Emails",   c1_phi_eml, max3, "bar-eml")}
    </div>
    <div class="legend">
      <span class="legend-item"><span class="legend-dot" style="background:#1f6feb"></span>URL</span>
      <span class="legend-item"><span class="legend-dot" style="background:#8957e5"></span>Message</span>
      <span class="legend-item"><span class="legend-dot" style="background:#2ea043"></span>Email</span>
    </div>
  </div>"""

    return chart1 + chart2 + chart3


# ─────────────────────────────────────────────────────────────────────────────
# BUILD ALERT ROWS
# Loops over ALERTS and produces one styled card per flagged record.
# ─────────────────────────────────────────────────────────────────────────────
def build_alert_rows(alerts):
    type_class = {"URL": "url", "Message": "message", "Email": "email"}
    rows = []
    for (user, rtype, content, sent, risk, reason) in alerts:
        tc        = type_class.get(rtype, "url")
        risk_key  = risk.lower()   # "high" or "medium"

        # Shorten very long content for display (full text still in title)
        display   = content if len(content) <= 70 else content[:67] + "..."
        safe_content = content.replace('"', "&quot;")

        # Pick an icon depending on risk level
        icon = "&#128680;" if risk == "High" else "&#9888;&#65039;"

        row = f"""
    <div class="alert-row risk-{risk_key}">
      <div class="alert-user">{icon} {user}</div>
      <div class="alert-meta">
        <span class="type-pill type-{tc}">{rtype}</span>
        <div class="alert-content" title="{safe_content}">{display}</div>
        <div class="alert-reason">&#128270; {reason}</div>
      </div>
      <div class="alert-right">
        <span class="risk-pill risk-{risk_key}">{risk} Risk</span>
        <span class="alert-sent">Sent: {sent}x</span>
      </div>
    </div>"""
        rows.append(row)
    return "\n".join(rows)


# ─────────────────────────────────────────────────────────────────────────────
# BUILD TABLE ROWS
# Loops over RECORDS and produces one HTML <tr> per record.
# ─────────────────────────────────────────────────────────────────────────────
def build_table_rows(records):
    type_class   = {"URL": "url", "Message": "message", "Email": "email"}
    result_class = {"Safe": "safe", "Suspicious": "suspicious", "Phishing": "phishing"}

    rows = []
    for i, (time, user, rtype, content, result, reason) in enumerate(records, start=1):
        tc = type_class.get(rtype, "url")
        rc = result_class.get(result, "safe")

        # Escape quotes in content so it doesn't break the title attribute
        safe_content = content.replace('"', "&quot;")

        row = f"""
        <tr>
          <td style="color:#484f58">{i}</td>
          <td class="time-cell">{time}</td>
          <td class="user-cell">{user}</td>
          <td><span class="type-pill type-{tc}">{rtype}</span></td>
          <td class="content-cell" title="{safe_content}">{content}</td>
          <td><span class="result-pill result-{rc}">{result}</span></td>
          <td><span class="reason reason-{rc}">{reason}</span></td>
        </tr>"""
        rows.append(row)
    return "\n".join(rows)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        rows        = build_table_rows(RECORDS[:10])   # show only first 10 records
        alert_rows  = build_alert_rows(ALERTS)
        charts      = build_charts(
            C1_SAFE_URL, C1_SAFE_MSG, C1_SAFE_EML,
            C1_SUS_URL,  C1_SUS_MSG,  C1_SUS_EML,
            C1_PHI_URL,  C1_PHI_MSG,  C1_PHI_EML,
        )
        page = HTML_TEMPLATE.format(
            TABLE_ROWS=rows,
            ALERT_ROWS=alert_rows,
            CHARTS=charts,
            SAFE_COUNT=TOTAL_SAFE,
            PHISH_COUNT=TOTAL_PHISHING,
            SUS_COUNT=TOTAL_SUSPICIOUS,
        )

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def log_message(self, format, *args):
        print(f"  [PhishShield] {args[0]} {args[1]}")


# ─────────────────────────────────────────────────────────────────────────────
# START SERVER
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    PORT = 8081

    server = HTTPServer(("", PORT), Handler)
    print(f"\n  PhishShield is running!")
    print(f"  Open your browser and go to: http://localhost:{PORT}\n")
    print(f"  Detection results: {TOTAL_SAFE} safe | {TOTAL_PHISHING} phishing | {TOTAL_SUSPICIOUS} suspicious\n")
    print("  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
