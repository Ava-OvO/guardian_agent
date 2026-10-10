"""Optional Streamlit presentation; the built-in dashboard needs no dependency."""

from agentguard.evaluation import latest, run


def main():
    try:
        import streamlit as st
    except ImportError as error:
        raise SystemExit("Install the optional dependency: pip install streamlit") from error

    st.set_page_config(page_title="AgentGuard Evaluation", page_icon="🛡️", layout="wide")
    st.title("🛡️ AgentGuard Security Evaluation")
    st.write("Compare policy, LLM, and hybrid decisions on the same synthetic cases. Policy remains the authority for permissions and data egress.")
    if st.button("Rerun local policy evaluation"):
        run()
    data = latest()
    st.caption("Results generated at " + data["generated_at"])
    policy = data["modes"]["policy"]["metrics"]
    a, b, c = st.columns(3)
    a.metric("Policy decision accuracy", "%0.1f%%" % (100 * policy["accuracy"]))
    b.metric("Unsafe allows", policy["unsafe_allow_count"])
    c.metric("Test cases", data["case_count"])
    if not data["llm_tested"]:
        st.info("LLM not tested. Set AGENTGUARD_LLM_URL, AGENTGUARD_LLM_MODEL, and AGENTGUARD_LLM_API_KEY, then run python3 -m agentguard.main evaluate --llm.")
    for mode, result in data["modes"].items():
        with st.expander({"policy":"Policy only","llm":"LLM only","hybrid":"Policy + LLM"}.get(mode, mode), expanded=mode=="policy"):
            st.json(result["metrics"])
            st.dataframe(result["cases"], use_container_width=True)
    st.caption("All demo data is synthetic. No real outbound tool is enabled.")


if __name__ == "__main__":
    main()
