"""
run with:  streamlit run app.py
"""

import streamlit as st

from UI.styles import GLOBAL_CSS
from UI.components import render_sidebar
from UI.pages import login, vault, add, export, import_

# ── page config & global CSS ──

st.set_page_config(page_title="Vault", layout="centered")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

# ── session defaults ──

for k, v in {
    "logged_in":      False,
    "username":       "",
    "master_pw":      "",
    "page":           "login",
    "confirm_action": {},
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── sidebar ──

if st.session_state.logged_in:
    render_sidebar()

# ── routing ──

if not st.session_state.logged_in:
    login.render()

PAGE_MAP = {
    "vault":  vault.render,
    "add":    add.render,
    "export": export.render,
    "import": import_.render,
}

page_fn = PAGE_MAP.get(st.session_state.page)
if page_fn:
    page_fn()
