import json
import streamlit as st

from UI.components import page_header, show_strength
from diffie_hellman_export import receive_import_bundle


def render() -> None:
    page_header(
        label="Module 4 — Diffie-Hellman Import",
        title="Import Vault",
        sub="Import a vault bundle that was exported to you.",
    )

    st.markdown(
        '<div class="dh-info">'
        "The bundle's ElGamal signature is verified before decryption. "
        "If verification fails the import is aborted. "
        "The vault is then re-encrypted under your chosen master password "
        "and re-signed with your key."
        "</div>",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader("Upload export_bundle.json", type="json")
    new_pw   = st.text_input(
        "New master password for this vault",
        type="password", placeholder="••••••••••",
    )
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
                with st.spinner("Verifying signatures and decrypting…"):
                    sender = receive_import_bundle(
                        bundle=bundle,
                        recipient_username=st.session_state.username,
                        new_master_password=new_pw,
                    )
                st.session_state.master_pw = new_pw
                st.success(f"Vault imported from **{sender}**. Master password updated.")
            except ValueError as e:
                st.error(str(e))
            except Exception as e:
                st.error(str(e))
