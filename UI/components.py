import streamlit as st
from zxcvbn import zxcvbn

STRENGTH_COLORS = ["#e05252", "#e05252", "#d4922a", "#3abf7e", "#27a864"]
STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def show_strength(pw: str, key_suffix: str = "") -> int | None:
    """
    Render a password strength bar and return the zxcvbn score (0–4),
    or None if pw is empty.
    """
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
        unsafe_allow_html=True,
    )
    if score < 2:
        tips = r.get("feedback", {}).get("suggestions", [])
        if tips:
            st.caption(" ".join(tips))
    return score


def page_header(label: str, title: str, sub: str) -> None:
    """Render the standard module label + section title + subtitle."""
    st.markdown(f'<div class="page-label">{label}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="section-sub">{sub}</div>', unsafe_allow_html=True)
    st.divider()


def render_sidebar() -> None:
    """Render the navigation sidebar for logged-in users."""
    with st.sidebar:
        st.markdown(
            f'<div style="font-family:var(--mono);font-size:0.7rem;color:var(--muted);'
            f'letter-spacing:0.08em;text-transform:uppercase;margin-bottom:4px">Logged in as</div>'
            f'<div style="font-family:var(--mono);font-size:1rem;font-weight:600;color:#e0e0f0;'
            f'margin-bottom:1.2rem">{st.session_state.username}</div>',
            unsafe_allow_html=True,
        )
        st.divider()
        nav = [
            ("🗄  My Vault",       "vault"),
            ("＋  Add Credential", "add"),
            ("↑   Export Vault",   "export"),
            ("↓   Import Vault",   "import"),
        ]
        for label, pg in nav:
            if st.button(label, use_container_width=True, key=f"nav_{pg}"):
                st.session_state.page = pg
                st.session_state.confirm_action = {}
                # st.rerun()
        st.divider()
        if st.button("Sign Out", use_container_width=True, key="signout"):
            for k in ["logged_in", "username", "master_pw", "confirm_action"]:
                st.session_state[k] = (
                    False if k == "logged_in"
                    else ({} if k == "confirm_action" else "")
                )
            st.session_state.page = "login"
            # st.rerun()
