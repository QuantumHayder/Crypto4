import json
import streamlit as st

from UI.components import page_header
from modules.vault_encryption import user_exists
from diffie_hellman_export import build_export_bundle


def render() -> None:
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
                    bundle = build_export_bundle(
                        sender=st.session_state.username,
                        recipient=recipient,
                        master_password=st.session_state.master_pw,
                    )
                st.success("Export package ready. Download and share it with the recipient.")
                st.download_button(
                    label="Download export_bundle.json",
                    data=json.dumps(bundle, indent=2),
                    file_name="export_bundle.json",
                    mime="application/json",
                )
            except Exception as e:
                st.error(str(e))
