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


# strength helpers

STRENGTH_COLORS = ["#e74c3c", "#e74c3c", "#e67e22", "#2ecc71", "#27ae60"]
STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

def show_strength(pw, key_suffix=""):
    if not pw:
        return
    r = zxcvbn(pw)
    score = r["score"]
    st.markdown(
        f"Strength: <span style='color:{STRENGTH_COLORS[score]};font-weight:700'>{STRENGTH_LABELS[score]}</span>",
        unsafe_allow_html=True
    )
    st.progress((score + 1) / 5)
    if score < 2:
        tips = r.get("feedback", {}).get("suggestions", [])
        if tips:
            st.caption(" ".join(tips))
    return score


# page setup

st.set_page_config(page_title="Password Manager", layout="centered")

st.markdown("""
<style>
    .entry-card {
        background: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 8px;
    }
    .entry-site { font-size: 1rem; font-weight: 700; color: #cdd6f4; }
    .entry-user { font-size: 0.85rem; color: #a6adc8; }
    .tag-ok   { background:#1e3a2f; color:#2ecc71; border-radius:6px; padding:2px 10px; font-size:0.78rem; }
    .tag-fail { background:#3a1e1e; color:#e74c3c; border-radius:6px; padding:2px 10px; font-size:0.78rem; }
</style>
""", unsafe_allow_html=True)


# session defaults
for k, v in {"logged_in": False, "username": "", "master_pw": "", "page": "login"}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# sidebar
if st.session_state.logged_in:
    with st.sidebar:
        st.markdown(f"### {st.session_state.username}")
        st.divider()
        nav = {"My Vault": "vault", "Add Credential": "add", "Export Vault": "export", "Import Vault": "import"}
        for label, pg in nav.items():
            if st.button(label, use_container_width=True):
                st.session_state.page = pg
        st.divider()
        if st.button("Log Out", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.master_pw = ""
            st.session_state.page = "login"
            st.rerun()


# LOGIN / REGISTER

if not st.session_state.logged_in:
    st.title("Secure Password Manager")
    st.caption("CMPS426 — Cairo University")
    st.divider()

    login_tab, reg_tab = st.tabs(["Log In", "Register"])

    with login_tab:
        uname = st.text_input("Username", key="li_u")
        pw    = st.text_input("Master Password", type="password", key="li_p")
        if st.button("Log In", type="primary", use_container_width=True):
            if not uname or not pw:
                st.error("Both fields required.")
            elif not user_exists(uname):
                st.error("User not found.")
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
        new_u  = st.text_input("Username", key="reg_u")
        new_pw = st.text_input("Master Password", type="password", key="reg_p")
        score  = show_strength(new_pw, "reg")

        if st.button("Register", type="primary", use_container_width=True):
            if not new_u or not new_pw:
                st.error("Both fields required.")
            elif user_exists(new_u):
                st.error("Username taken.")
            elif score is not None and score < 3:
                st.error("Password too weak, pick something stronger.")
            else:
                try:
                    pub, priv = generate_keypair(new_u)
                    save_keypair(pub, priv, new_u)
                    init_vault(new_u, new_pw)
                    st.success("Account created, you can log in now.")
                except Exception as e:
                    st.error(str(e))

    st.stop()


# VAULT

if st.session_state.page == "vault":
    st.title("My Vault")

    try:
        entries = load_entries(st.session_state.username, st.session_state.master_pw)
    except Exception as e:
        st.error(str(e))
        st.stop()

    pub, _ = load_keypair(st.session_state.username)
    sig_ok = verify_vault(vault_path(st.session_state.username), pub)
    if sig_ok:
        st.markdown('<span class="tag-ok">✔ signature valid</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="tag-fail">✘ signature invalid — vault may be tampered</span>', unsafe_allow_html=True)

    st.divider()

    if not entries:
        st.info("Vault is empty. Add a credential from the sidebar.")
    else:
        st.write(f"{len(entries)} stored")
        for i, e in enumerate(entries):
            st.markdown(
                f'<div class="entry-card">'
                f'<div class="entry-site">{e["website"]}</div>'
                f'<div class="entry-user">{e["username"]}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
            c1, c2, c3 = st.columns([2, 2, 1])
            with c1:
                if st.button("Show password", key=f"show_{i}"):
                    st.code(e["password"])
            with c2:
                with st.expander("Edit"):
                    ns = st.text_input("Website",  value=e["website"],  key=f"es_{i}")
                    nu = st.text_input("Username", value=e["username"], key=f"eu_{i}")
                    np = st.text_input("Password", value=e["password"], key=f"ep_{i}", type="password")
                    if st.button("Save", key=f"sv_{i}"):
                        entries[i] = {"website": ns, "username": nu, "password": np}
                        save_entries(st.session_state.username, st.session_state.master_pw, entries)
                        st.success("Saved.")
                        st.rerun()
            with c3:
                if st.button("Delete", key=f"del_{i}"):
                    entries.pop(i)
                    save_entries(st.session_state.username, st.session_state.master_pw, entries)
                    st.rerun()


# ADD

elif st.session_state.page == "add":
    st.title("Add Credential")
    st.divider()

    site = st.text_input("Website")
    user = st.text_input("Username / Email")
    pw   = st.text_input("Password", type="password")
    show_strength(pw, "add")

    if st.button("Save", type="primary", use_container_width=True):
        if not site or not user or not pw:
            st.error("All fields required.")
        else:
            try:
                entries = load_entries(st.session_state.username, st.session_state.master_pw)
                entries.append({"website": site, "username": user, "password": pw})
                save_entries(st.session_state.username, st.session_state.master_pw, entries)
                st.success(f"Saved entry for {site}.")
            except Exception as e:
                st.error(str(e))


# EXPORT

elif st.session_state.page == "export":
    st.title("Export Vault")
    st.caption("Sends your vault to another registered user via DH key exchange.")
    st.divider()

    recipient = st.text_input("Recipient username")

    if st.button("Generate export package", type="primary", use_container_width=True):
        if not recipient:
            st.error("Enter a recipient username.")
        elif not user_exists(recipient):
            st.error(f"No user '{recipient}' found.")
        elif recipient == st.session_state.username:
            st.error("Can't export to yourself.")
        else:
            try:
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

                st.success("Package ready.")
                st.download_button(
                    label="Download export_bundle.json",
                    data=json.dumps(bundle, indent=2),
                    file_name="export_bundle.json",
                    mime="application/json",
                )

            except Exception as e:
                st.error(str(e))


# IMPORT

elif st.session_state.page == "import":
    st.title("Import Vault")
    st.caption("Import a vault someone exported to you.")
    st.divider()

    uploaded = st.file_uploader("Upload export_bundle.json", type="json")
    new_pw   = st.text_input("New master password for the imported vault", type="password")
    show_strength(new_pw, "imp")

    if st.button("Import", type="primary", use_container_width=True):
        if not uploaded:
            st.error("Upload the bundle file first.")
        elif not new_pw:
            st.error("Set a master password.")
        else:
            try:
                bundle = json.loads(uploaded.read())

                if bundle["recipient"] != st.session_state.username:
                    st.error(f"This bundle is for '{bundle['recipient']}', not you.")
                    st.stop()

                sender = bundle["sender"]
                d1_pub, _ = load_keypair(sender)
                d2_pub, d2_priv = load_keypair(st.session_state.username)

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
                st.success(f"Vault imported from {sender}. Master password updated.")

            except Exception as e:
                st.error(str(e))