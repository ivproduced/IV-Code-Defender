# OWASP LLM and Agentic code review

`/vuln-scan` explicitly checks LLM and agent code against the [OWASP Top 10
for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
and the [OWASP Top 10 for Agentic Applications
2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
The scan brief names all ten `LLM01:2026`–`LLM10:2026` and all ten
`ASI01`–`ASI10` categories. Its recon step includes prompt assembly, RAG,
model outputs, tools, credentials, memory, agent messages, approvals, and
resource limits as focus areas when relevant.

```text
/vuln-scan <repository>
/triage <repository>/VULN-FINDINGS.json --repo <repository>
```

Findings include an `owasp_refs` list, such as
`["LLM01:2026", "ASI01"]`. The scanner requires a reachable path from
attacker-controlled input to a security impact; the OWASP code is a label,
not proof. `/triage` checks the cited source, authorization boundary, and
protections before accepting a finding. Mere user input in a prompt is
insufficient. Attacker-triggered model or tool loops with material cost can
qualify as unbounded consumption; ordinary missing rate limiting does not.

This is static code review. Risks that depend on model behavior, provider
configuration, training data outside the checkout, or runtime state may need
manual or execution-based validation. The existing `vuln-pipeline` profiles
still require target-specific replay and detection signals for verified
findings; this change does not turn an OWASP label into a verified PoC.
