import streamlit as st

from UI.components import show_strength
from vault_service import user_exists, register_user, load_entries


def render() -> None:
    st.markdown('<div class="login-wrap">', unsafe_allow_html=True)
    st.markdown(
        '<div class="login-brand">Crypto-4 Password Manager</div>',
        unsafe_allow_html=True,
    )

    login_tab, reg_tab = st.tabs(["sign_in", "register"])

    with login_tab:
        _render_login()

    with reg_tab:
        _render_register()

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


def _render_login() -> None:
    uname = st.text_input("Username", key="li_u", placeholder="your username")
    pw    = st.text_input("Master Password", type="password", key="li_p", placeholder="••••••••••")

    if st.button("Sign In →", type="primary", use_container_width=True, key="li_btn"):
        if not uname or not pw:
            st.error("Both fields are required.")
        elif not user_exists(uname):
            st.error("No account found for that username.")
        else:
            try:
                load_entries(uname, pw)   # raises on bad password or bad signature
                st.session_state.logged_in = True
                st.session_state.username  = uname
                st.session_state.master_pw = pw
                st.session_state.page      = "vault"
                st.rerun()
            except Exception as e:
                st.error(str(e))


def _render_register() -> None:
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
                register_user(new_u, new_pw)
                st.success("Account created. You can sign in now.")
            except Exception as e:
                st.error(str(e))
