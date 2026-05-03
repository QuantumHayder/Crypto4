import json
import streamlit as st

from UI.components import page_header
from vault_service import user_exists, build_export_bundle


def render() -> None:
    st.markdown(
        '<div class="dh-info">'
        "Key Exchange: ephemeral DH keypairs are generated, mutually signed with ElGamal, "
        "and used to derive a one-time AES-256 session key. The vault is re-encrypted "
        "under this session key before transmission."
        "</div>",
        unsafe_allow_html=True,
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
                    bundle = build_export_bundle(
                        sender=st.session_state.username,
                        recipient=recipient,
                        master_password=st.session_state.master_pw,
                    )
                st.success("Export package ready. Download and share it with the recipient.")
                st.download_button(
                    label="⬇ Download export_bundle.json",
                    data=json.dumps(bundle, indent=2),
                    file_name="export_bundle.json",
                    mime="application/json",
                )
            except Exception as e:
                st.error(str(e))
