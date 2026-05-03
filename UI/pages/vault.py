import streamlit as st

from vault_service import load_entries, save_entries, verify_master_password


def render() -> None:
    try:
        entries = load_entries(st.session_state.username, st.session_state.master_pw)
    except Exception as e:
        st.error(str(e))
        st.stop()

    # Signature is already verified inside load_entries; if we're here it passed.
    sig_html  = '<span class="sig-ok">✔ signature valid</span>'
    count     = len(entries)
    count_html = (
        f'<span class="count-badge">'
        f'{count} credential{"s" if count != 1 else ""} stored'
        f'</span>'
    )

    st.markdown(
        f'<div class="vault-header"><h1>My Vault</h1>{sig_html}</div>{count_html}',
        unsafe_allow_html=True,
    )
    st.divider()

    if not entries:
        st.markdown(
            '<div style="text-align:center;padding:3rem 0;color:var(--muted);'
            'font-family:var(--mono);font-size:0.85rem">'
            'vault is empty<br>'
            '<span style="font-size:0.72rem;opacity:0.6">add a credential from the sidebar</span>'
            "</div>",
            unsafe_allow_html=True,
        )
        return

    for i, e in enumerate(entries):
        _render_entry(i, e, entries)


def _render_entry(i: int, e: dict, entries: list[dict]) -> None:
    st.markdown(
        f'<div class="entry-card">'
        f'<div class="entry-site">{e["website"]}</div>'
        f'<div class="entry-user">{e["username"]}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns([3, 2, 2])

    with c1:
        if st.button("Show password", key=f"showbtn_{i}"):
            current = st.session_state.confirm_action.get(i)
            st.session_state.confirm_action = {i: "show"} if current != "show" else {}
            st.rerun()
    with c2:
        if st.button("Edit", key=f"editbtn_{i}"):
            current = st.session_state.confirm_action.get(i)
            st.session_state.confirm_action = {i: "edit"} if current != "edit" else {}
            st.rerun()
    with c3:
        if st.button("Delete", key=f"delbtn_{i}"):
            current = st.session_state.confirm_action.get(i)
            st.session_state.confirm_action = {i: "delete"} if current != "delete" else {}
            st.rerun()

    action = st.session_state.confirm_action.get(i)

    if action == "show":
        _confirm_show(i, e)
    elif action == "edit":
        _confirm_edit(i, e, entries)
    elif action == "delete":
        _confirm_delete(i, e, entries)


def _confirm_password_input(key: str) -> str:
    """Render master password confirmation input and return its value."""
    return st.text_input(
        "Master Password", type="password", key=key, placeholder="••••••••••"
    )


def _confirm_show(i: int, e: dict) -> None:
    st.markdown(
        f'<div class="confirm-box">'
        f'<p>confirm identity to show the password for "{e["website"]}"</p>'
        f'</div>',
        unsafe_allow_html=True,
    )
    confirm_pw = _confirm_password_input(f"show_pw_{i}")
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


def _confirm_edit(i: int, e: dict, entries: list[dict]) -> None:
    st.markdown(
        '<div class="confirm-box"><p>confirm identity to edit this entry</p></div>',
        unsafe_allow_html=True,
    )
    confirm_pw = _confirm_password_input(f"edit_pw_{i}")
    ns  = st.text_input("Website",  value=e["website"],  key=f"es_{i}")
    nu  = st.text_input("Username", value=e["username"], key=f"eu_{i}")
    np_ = st.text_input("Password", value=e["password"], key=f"ep_{i}", type="password")
    col_save, col_cancel = st.columns([1, 1])
    with col_save:
        if st.button("Save changes", key=f"sv_{i}", type="primary"):
            if not confirm_pw:
                st.error("Enter your master password to confirm.")
            elif not verify_master_password(st.session_state.username, confirm_pw):
                st.error("Incorrect master password.")
            else:
                entries[i] = {"website": ns, "username": nu, "password": np_}
                save_entries(st.session_state.username, st.session_state.master_pw, entries)
                st.session_state.confirm_action = {}
                st.rerun()
    with col_cancel:
        if st.button("Cancel", key=f"cancel_edit_{i}"):
            st.session_state.confirm_action = {}
            st.rerun()


def _confirm_delete(i: int, e: dict, entries: list[dict]) -> None:
    st.markdown(
        f'<div class="confirm-box"><p>⚠ confirm deletion of "{e["website"]}"</p></div>',
        unsafe_allow_html=True,
    )
    confirm_pw = _confirm_password_input(f"del_pw_{i}")
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
