import streamlit as st

from UI.components import page_header, show_strength
from vault_service import save_entries, load_entries, verify_master_password


def render() -> None:
    site = st.text_input("Website / Service", placeholder="e.g. github.com")
    user = st.text_input("Username / Email",  placeholder="e.g. user@example.com")
    pw   = st.text_input("Password", type="password", placeholder="••••••••••")
    show_strength(pw, "add")

    st.markdown("---")
    st.markdown(
        '<div style="font-size:0.75rem;color:var(--muted);font-family:var(--mono);margin-bottom:6px">'
        "master password required to write to vault</div>",
        unsafe_allow_html=True,
    )
    confirm_pw = st.text_input(
        "Master Password", type="password",
        key="add_confirm_pw", placeholder="••••••••••",
    )

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
