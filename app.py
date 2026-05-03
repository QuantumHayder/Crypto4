"""
run with:  streamlit run app.py
"""

import json
import streamlit as st
from pathlib import Path
from zxcvbn import zxcvbn

from modules.elgamal import generate_keypair, save_keypair, load_keypair
from modules.encryption import AES_Encryption
from modules.sign import sign_vault
from modules.verify import verify_vault
from diffie_hellman_export import (
    device1_start_exchange,
    device2_respond_to_exchange,
    export_vault,
    import_vault,
    DHPrivateKey,
)

VAULTS_DIR = Path("vaults")


# helpers

def vault_path(username):
    return VAULTS_DIR / username / "vault.json"

def user_exists(username):
    return vault_path(username).exists()

def init_vault(username, master_password):
    path = vault_path(username)
    path.parent.mkdir(parents=True, exist_ok=True)
    empty = json.dumps({"entries": []})
    enc = AES_Encryption(master_password).encrypt(empty)
    path.write_text(json.dumps({"encrypted_vault": enc, "signature": {}}, indent=2), encoding="utf-8")
    pub, priv = load_keypair(username)
    sign_vault(path, pub, priv)

def load_entries(username, master_pw):
    path = vault_path(username)
    pub, _ = load_keypair(username)
    if not verify_vault(path, pub):
        raise Exception("Vault signature check failed — vault may have been tampered with.")
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        plain = AES_Encryption(master_pw).decrypt(data["encrypted_vault"])
    except Exception:
        raise Exception("Wrong master password.")
    return json.loads(plain)["entries"]

def save_entries(username, master_pw, entries):
    path = vault_path(username)
    enc = AES_Encryption(master_pw).encrypt(json.dumps({"entries": entries}))
    path.write_text(json.dumps({"encrypted_vault": enc, "signature": {}}, indent=2), encoding="utf-8")
    pub, priv = load_keypair(username)
    sign_vault(path, pub, priv)

def verify_master_password(username, pw):
    """Returns True if pw correctly decrypts the vault."""
    try:
        load_entries(username, pw)
        return True
    except Exception:
        return False

STRENGTH_COLORS = ["#e05252", "#e05252", "#d4922a", "#3abf7e", "#27a864"]
STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

def show_strength(pw, key_suffix=""):
    if not pw:
        return None
    r = zxcvbn(pw)
    score = r["score"]
    filled = score + 1
    bars_html = ""
    for i in range(5):
        color = STRENGTH_COLORS[score] if i < filled else "#2a2a3a"
        bars_html += f'<div style="flex:1;height:4px;background:{color};border-radius:2px;"></div>'
    st.markdown(
        f'<div style="display:flex;gap:4px;margin:6px 0 2px">{bars_html}</div>'
        f'<p style="font-size:0.78rem;color:{STRENGTH_COLORS[score]};margin:0 0 8px">'
        f'{STRENGTH_LABELS[score]}</p>',
        unsafe_allow_html=True
    )
    if score < 2:
        tips = r.get("feedback", {}).get("suggestions", [])
        if tips:
            st.caption(" ".join(tips))
    return score


# page config & global CSS

st.set_page_config(page_title="Vault", layout="centered")

st.markdown("""
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
""", unsafe_allow_html=True)


# session defaults

for k, v in {
    "logged_in": False,
    "username": "",
    "master_pw": "",
    "page": "login",
    # per-entry confirm state: { index -> "edit"|"delete" }
    "confirm_action": {},
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# sidebar (logged in)

if st.session_state.logged_in:
    with st.sidebar:
        st.markdown(
            f'<div style="font-family:var(--mono);font-size:0.7rem;color:var(--muted);'
            f'letter-spacing:0.08em;text-transform:uppercase;margin-bottom:4px">Logged in as</div>'
            f'<div style="font-family:var(--mono);font-size:1rem;font-weight:600;color:#e0e0f0;'
            f'margin-bottom:1.2rem">{st.session_state.username}</div>',
            unsafe_allow_html=True
        )
        st.divider()
        nav = [
            ("🗄  My Vault",         "vault"),
            ("＋  Add Credential",   "add"),
            ("↑   Export Vault",     "export"),
            ("↓   Import Vault",     "import"),
        ]
        for label, pg in nav:
            active = st.session_state.page == pg
            style = "border-color:var(--accent) !important;color:var(--accent) !important;" if active else ""
            if st.button(label, use_container_width=True, key=f"nav_{pg}"):
                st.session_state.page = pg
                st.session_state.confirm_action = {}
                st.rerun()
        st.divider()
        if st.button("Sign Out", use_container_width=True, key="signout"):
            for k in ["logged_in", "username", "master_pw", "confirm_action"]:
                st.session_state[k] = False if k == "logged_in" else ({} if k == "confirm_action" else "")
            st.session_state.page = "login"
            st.rerun()


# LOGIN / REGISTER

if not st.session_state.logged_in:
    st.markdown('<div class="login-wrap">', unsafe_allow_html=True)
    st.markdown(
        '<div class="login-brand">vault</div>'
        '<div class="login-sub">CMPS426 · Cairo University · Secure Password Manager</div>',
        unsafe_allow_html=True
    )

    login_tab, reg_tab = st.tabs(["sign_in", "register"])

    with login_tab:
        uname = st.text_input("Username", key="li_u", placeholder="your username")
        pw    = st.text_input("Master Password", type="password", key="li_p", placeholder="••••••••••")
        if st.button("Sign In →", type="primary", use_container_width=True, key="li_btn"):
            if not uname or not pw:
                st.error("Both fields are required.")
            elif not user_exists(uname):
                st.error("No account found for that username.")
            else:
                try:
                    load_entries(uname, pw)
                    st.session_state.logged_in = True
                    st.session_state.username  = uname
                    st.session_state.master_pw = pw
                    st.session_state.page      = "vault"
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

    with reg_tab:
        new_u  = st.text_input("Username", key="reg_u", placeholder="choose a username")
        new_pw = st.text_input("Master Password", type="password", key="reg_p", placeholder="••••••••••")
        score  = show_strength(new_pw, "reg")
        st.caption("Master password must be Strong (score ≥ 3). It cannot be recovered if lost.")

        if st.button("Create Account →", type="primary", use_container_width=True, key="reg_btn"):
            if not new_u or not new_pw:
                st.error("Both fields are required.")
            elif user_exists(new_u):
                st.error("That username is already taken.")
            elif score is not None and score < 3:
                st.error("Master password is too weak — choose something stronger.")
            else:
                try:
                    pub, priv = generate_keypair(new_u)
                    save_keypair(pub, priv, new_u)
                    init_vault(new_u, new_pw)
                    st.success("Account created. You can sign in now.")
                except Exception as e:
                    st.error(str(e))

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()


# MY VAULT

if st.session_state.page == "vault":
    try:
        entries = load_entries(st.session_state.username, st.session_state.master_pw)
    except Exception as e:
        st.error(str(e))
        st.stop()

    pub, _ = load_keypair(st.session_state.username)
    sig_ok = verify_vault(vault_path(st.session_state.username), pub)

    sig_html = (
        '<span class="sig-ok">✔ signature valid</span>'
        if sig_ok else
        '<span class="sig-fail">✘ signature invalid — vault may be tampered</span>'
    )
    count_html = f'<span class="count-badge">{len(entries)} credential{"s" if len(entries) != 1 else ""} stored</span>'

    st.markdown(
        f'<div class="vault-header">'
        f'<h1>My Vault</h1>{sig_html}'
        f'</div>'
        f'{count_html}',
        unsafe_allow_html=True
    )
    st.divider()

    if not entries:
        st.markdown(
            '<div style="text-align:center;padding:3rem 0;color:var(--muted);font-family:var(--mono);font-size:0.85rem">'
            'vault is empty<br><span style="font-size:0.72rem;opacity:0.6">add a credential from the sidebar</span>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        for i, e in enumerate(entries):
            st.markdown(
                f'<div class="entry-card">'
                f'<div class="entry-site">{e["website"]}</div>'
                f'<div class="entry-user">{e["username"]}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

            c1, c2, c3 = st.columns([3, 2, 2])

            # Show password
            with c1:
                if st.button("Show password", key=f"showbtn_{i}"):
                    current = st.session_state.confirm_action.get(i)
                    st.session_state.confirm_action = {i: "show"} if current != "show" else {}
                    st.rerun()

            # Confirm: Show password
            if st.session_state.confirm_action.get(i) == "show":
                st.markdown(
                    f'<div class="confirm-box"><p>confirm identity to show the password for "{e["website"]}"</p></div>',
                    unsafe_allow_html=True
                )
                confirm_pw = st.text_input("Master Password", type="password", key=f"show_pw_{i}", placeholder="••••••••••")
                col_show, col_cancel = st.columns([1, 1])
                with col_show:
                    if st.button("Show password", key=f"confirm_show_{i}", type="primary"):
                        if not confirm_pw:
                            st.error("Enter your master password to confirm.")
                        elif not verify_master_password(st.session_state.username, confirm_pw):
                            st.error("Incorrect master password.")
                        else:
                            st.code(e["password"], language=None)
                            st.session_state.confirm_action = {}
                with col_cancel:
                    if st.button("Cancel", key=f"cancel_show_{i}"):
                        st.session_state.confirm_action = {}
                        st.rerun()

            # Edit
            with c2:
                edit_key = f"edit_{i}"
                if st.button("Edit", key=f"editbtn_{i}"):
                    current = st.session_state.confirm_action.get(i)
                    st.session_state.confirm_action = {i: "edit"} if current != "edit" else {}
                    st.rerun()

            # Delete
            with c3:
                if st.button("Delete", key=f"delbtn_{i}"):
                    current = st.session_state.confirm_action.get(i)
                    st.session_state.confirm_action = {i: "delete"} if current != "delete" else {}
                    st.rerun()

            # Confirm: Edit
            if st.session_state.confirm_action.get(i) == "edit":
                st.markdown('<div class="confirm-box"><p>confirm identity to edit this entry</p>', unsafe_allow_html=True)
                confirm_pw = st.text_input("Master Password", type="password", key=f"edit_pw_{i}", placeholder="••••••••••")
                ns = st.text_input("Website",  value=e["website"],  key=f"es_{i}")
                nu = st.text_input("Username", value=e["username"], key=f"eu_{i}")
                np = st.text_input("Password", value=e["password"], key=f"ep_{i}", type="password")
                col_save, col_cancel = st.columns([1, 1])
                with col_save:
                    if st.button("Save changes", key=f"sv_{i}", type="primary"):
                        if not confirm_pw:
                            st.error("Enter your master password to confirm.")
                        elif not verify_master_password(st.session_state.username, confirm_pw):
                            st.error("Incorrect master password.")
                        else:
                            entries[i] = {"website": ns, "username": nu, "password": np}
                            save_entries(st.session_state.username, st.session_state.master_pw, entries)
                            st.session_state.confirm_action = {}
                            st.rerun()
                with col_cancel:
                    if st.button("Cancel", key=f"cancel_edit_{i}"):
                        st.session_state.confirm_action = {}
                        st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

            # Confirm: Delete
            if st.session_state.confirm_action.get(i) == "delete":
                st.markdown(
                    f'<div class="confirm-box"><p>⚠ confirm deletion of "{e["website"]}"</p></div>',
                    unsafe_allow_html=True
                )
                confirm_pw = st.text_input("Master Password", type="password", key=f"del_pw_{i}", placeholder="••••••••••")
                col_del, col_cancel = st.columns([1, 1])
                with col_del:
                    if st.button("Confirm Delete", key=f"confirm_del_{i}", type="primary"):
                        if not confirm_pw:
                            st.error("Enter your master password to confirm.")
                        elif not verify_master_password(st.session_state.username, confirm_pw):
                            st.error("Incorrect master password.")
                        else:
                            entries.pop(i)
                            save_entries(st.session_state.username, st.session_state.master_pw, entries)
                            st.session_state.confirm_action = {}
                            st.rerun()
                with col_cancel:
                    if st.button("Cancel", key=f"cancel_del_{i}"):
                        st.session_state.confirm_action = {}
                        st.rerun()


# ADD CREDENTIAL

elif st.session_state.page == "add":
    st.markdown('<div class="page-label">Module 2 — Vault Encryption</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Add Credential</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Entry is encrypted immediately with your master password and re-signed.</div>', unsafe_allow_html=True)
    st.divider()

    site    = st.text_input("Website / Service", placeholder="e.g. github.com")
    user    = st.text_input("Username / Email",  placeholder="e.g. user@example.com")
    pw      = st.text_input("Password",          type="password", placeholder="••••••••••")
    show_strength(pw, "add")

    st.markdown("---")
    st.markdown(
        '<div style="font-size:0.75rem;color:var(--muted);font-family:var(--mono);margin-bottom:6px">'
        'master password required to write to vault</div>',
        unsafe_allow_html=True
    )
    confirm_pw = st.text_input("Master Password", type="password", key="add_confirm_pw", placeholder="••••••••••")

    if st.button("Save to Vault →", type="primary", use_container_width=True):
        if not site or not user or not pw:
            st.error("All credential fields are required.")
        elif not confirm_pw:
            st.error("Enter your master password to confirm.")
        elif not verify_master_password(st.session_state.username, confirm_pw):
            st.error("Incorrect master password.")
        else:
            try:
                entries = load_entries(st.session_state.username, st.session_state.master_pw)
                entries.append({"website": site, "username": user, "password": pw})
                save_entries(st.session_state.username, st.session_state.master_pw, entries)
                st.success(f"Credential for **{site}** saved and vault re-signed.")
            except Exception as e:
                st.error(str(e))


# EXPORT VAULT

elif st.session_state.page == "export":
    st.markdown('<div class="page-label">Module 4 — Diffie-Hellman Export</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Export Vault</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Securely transfer your vault to another registered user.</div>', unsafe_allow_html=True)
    st.divider()

    st.markdown(
        '<div class="dh-info">'
        'Key Exchange: ephemeral DH keypairs are generated, mutually signed with ElGamal, '
        'and used to derive a one-time AES-256 session key. The vault is re-encrypted '
        'under this session key before transmission.'
        '</div>',
        unsafe_allow_html=True
    )

    recipient = st.text_input("Recipient username", placeholder="their username on this system")

    if st.button("Generate Export Package →", type="primary", use_container_width=True):
        if not recipient:
            st.error("Enter the recipient's username.")
        elif not user_exists(recipient):
            st.error(f"No registered user '{recipient}'.")
        elif recipient == st.session_state.username:
            st.error("You cannot export to yourself.")
        else:
            try:
                with st.spinner("Running DH key exchange and encrypting vault…"):
                    d1_pub, d1_priv = load_keypair(st.session_state.username)
                    d2_pub, d2_priv = load_keypair(recipient)

                    d1_dh_pub, d1_dh_priv, d1_signed_dh = device1_start_exchange(d1_pub, d1_priv)
                    d2_dh_pub, d2_dh_priv, d2_signed_dh = device2_respond_to_exchange(
                        d1_signed_dh, d1_pub, d2_pub, d2_priv
                    )

                    pkg = export_vault(
                        vault_path=vault_path(st.session_state.username),
                        master_password=st.session_state.master_pw,
                        d1_dh_priv=d1_dh_priv,
                        d2_signed_pkg=d2_signed_dh,
                        d1_public_key=d1_pub,
                        d1_private_key=d1_priv,
                        d2_public_key=d2_pub,
                    )

                    bundle = {
                        "export_pkg":   pkg,
                        "d1_signed_dh": d1_signed_dh,
                        "d2_dh_priv":   d2_dh_priv.value,
                        "sender":       st.session_state.username,
                        "recipient":    recipient,
                    }

                st.success("Export package ready. Download and share it with the recipient.")
                st.download_button(
                    label="⬇ Download export_bundle.json",
                    data=json.dumps(bundle, indent=2),
                    file_name="export_bundle.json",
                    mime="application/json",
                )
            except Exception as e:
                st.error(str(e))


# IMPORT VAULT

elif st.session_state.page == "import":
    st.markdown('<div class="page-label">Module 4 — Diffie-Hellman Import</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Import Vault</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Import a vault bundle that was exported to you.</div>', unsafe_allow_html=True)
    st.divider()

    st.markdown(
        '<div class="dh-info">'
        "The bundle's ElGamal signature is verified before decryption. "
        'If verification fails the import is aborted. '
        'The vault is then re-encrypted under your chosen master password and re-signed with your key.'
        '</div>',
        unsafe_allow_html=True
    )

    uploaded = st.file_uploader("Upload export_bundle.json", type="json")
    new_pw   = st.text_input("New master password for this vault", type="password", placeholder="••••••••••")
    show_strength(new_pw, "imp")
    st.caption("This will replace your current vault. Choose a strong password.")

    if st.button("Import →", type="primary", use_container_width=True):
        if not uploaded:
            st.error("Upload the bundle file first.")
        elif not new_pw:
            st.error("Set a master password for the imported vault.")
        else:
            try:
                bundle = json.loads(uploaded.read())

                if bundle["recipient"] != st.session_state.username:
                    st.error(f"This bundle is addressed to '{bundle['recipient']}', not you.")
                    st.stop()

                sender     = bundle["sender"]
                d1_pub, _  = load_keypair(sender)
                d2_pub, d2_priv = load_keypair(st.session_state.username)

                with st.spinner("Verifying signatures and decrypting…"):
                    import_vault(
                        export_pkg=bundle["export_pkg"],
                        d2_dh_priv=DHPrivateKey(value=bundle["d2_dh_priv"]),
                        d1_signed_dh_pkg=bundle["d1_signed_dh"],
                        d1_public_key=d1_pub,
                        d2_public_key=d2_pub,
                        d2_private_key=d2_priv,
                        new_master_password=new_pw,
                        output_vault_path=vault_path(st.session_state.username),
                    )

                st.session_state.master_pw = new_pw
                st.success(f"Vault imported from **{sender}**. Master password updated.")

            except Exception as e:
                st.error(str(e))