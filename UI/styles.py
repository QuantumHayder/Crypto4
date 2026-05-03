GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

:root {
    --bg:        #0d0d12;
    --surface:   #13131c;
    --border:    #1f1f2e;
    --border2:   #2a2a3d;
    --text:      #c8c8d8;
    --muted:     #585870;
    --accent:    #5b8af5;
    --accent2:   #7c6af7;
    --danger:    #e05252;
    --ok:        #3abf7e;
    --warn:      #d4922a;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
}

html, body, [class*="css"] {
    font-family: var(--sans) !important;
    background: var(--bg) !important;
    color: var(--text) !important;
}

/* hide streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }
.block-container { padding-top: 2.5rem !important; max-width: 680px !important; }

/* sidebar */
[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

/* inputs */
input, textarea {
    background: var(--surface) !important;
    border: 1px solid var(--border2) !important;
    color: var(--text) !important;
    border-radius: 6px !important;
    font-family: var(--sans) !important;
}
input:focus, textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px rgba(91,138,245,0.15) !important;
}
label { color: var(--muted) !important; font-size: 0.78rem !important; letter-spacing: 0.06em !important; text-transform: uppercase !important; }

/* primary button */
.stButton > button[kind="primary"],
.stButton > button[data-testid*="primary"] {
    background: var(--accent) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: var(--mono) !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.04em !important;
    padding: 0.5rem 1.2rem !important;
    transition: opacity 0.15s;
}
.stButton > button[kind="primary"]:hover { opacity: 0.85 !important; }

/* secondary button */
.stButton > button {
    background: transparent !important;
    color: var(--text) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 6px !important;
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
}
.stButton > button:hover { border-color: var(--accent) !important; color: var(--accent) !important; }

/* tabs */
[data-testid="stTabs"] [role="tab"] {
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.04em !important;
    color: var(--muted) !important;
}
[data-testid="stTabs"] [aria-selected="true"] { color: var(--text) !important; }

/* divider */
hr { border-color: var(--border) !important; margin: 1.2rem 0 !important; }

/* alerts */
[data-testid="stAlert"] { border-radius: 6px !important; font-size: 0.85rem !important; }

/* expander */
[data-testid="stExpander"] {
    background: var(--surface) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 8px !important;
}

/* code */
code, .stCode { font-family: var(--mono) !important; background: var(--surface) !important; }

/* file uploader */
[data-testid="stFileUploader"] {
    background: var(--surface) !important;
    border: 1px dashed var(--border2) !important;
    border-radius: 8px !important;
}

/* custom components */
.vault-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 1.5rem;
}
.vault-header h1 {
    font-family: var(--mono) !important;
    font-size: 1.4rem !important;
    font-weight: 600 !important;
    letter-spacing: -0.01em !important;
    margin: 0 !important;
    color: #e0e0ee !important;
}
.page-label {
    font-family: var(--mono);
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.4rem;
}
.entry-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 14px 18px 10px;
    margin-bottom: 10px;
    transition: border-color 0.15s;
}
.entry-card:hover { border-color: var(--accent2); border-left-color: var(--accent2); }
.entry-site {
    font-family: var(--mono);
    font-size: 0.95rem;
    font-weight: 600;
    color: #e0e0f0;
    margin-bottom: 2px;
}
.entry-user {
    font-size: 0.8rem;
    color: var(--muted);
}
.sig-ok {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(58,191,126,0.1);
    color: var(--ok);
    border: 1px solid rgba(58,191,126,0.25);
    border-radius: 4px;
    padding: 3px 12px;
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.05em;
}
.sig-fail {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(224,82,82,0.1);
    color: var(--danger);
    border: 1px solid rgba(224,82,82,0.25);
    border-radius: 4px;
    padding: 3px 12px;
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.05em;
}
.count-badge {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    letter-spacing: 0.06em;
}
.confirm-box {
    background: rgba(212,146,42,0.07);
    border: 1px solid rgba(212,146,42,0.25);
    border-radius: 8px;
    padding: 14px 16px;
    margin: 8px 0;
}
.confirm-box p {
    font-size: 0.8rem;
    color: var(--warn);
    margin: 0 0 10px;
    font-family: var(--mono);
}
.login-wrap {
    max-width: 420px;
    margin: 3rem auto 0;
}
.login-brand {
    font-family: var(--mono);
    font-size: 1.5rem;
    font-weight: 600;
    color: #e0e0f0;
    letter-spacing: -0.02em;
    margin-bottom: 2px;
}
.login-sub {
    font-size: 0.78rem;
    color: var(--muted);
    letter-spacing: 0.06em;
    margin-bottom: 2rem;
}
.section-title {
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 600;
    color: #e0e0f0;
    margin-bottom: 0.2rem;
}
.section-sub {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 1.2rem;
}
.dh-info {
    background: rgba(91,138,245,0.07);
    border: 1px solid rgba(91,138,245,0.2);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.78rem;
    color: #8899cc;
    font-family: var(--mono);
    margin-bottom: 1rem;
}
</style>
"""
