"""M20 executable assurance policy definitions."""
SECURITY_CONTROLS={
"deny_cross_case":"Case authorization must run before every case-scoped read/write.",
"deny_original_mutation":"Original evidence storage is read-only to analysis workers.",
"deny_external_ai":"External AI is disabled unless an audited expiring grant exists.",
"deny_uncited_ai":"Assistant persistence requires citations or unsupported=true.",
"deny_unverified_verdict":"Analysis results require human verification.",
"deny_impersonation":"No impersonation capability exists in v1.",
}
def controls()->dict[str,str]: return dict(SECURITY_CONTROLS)
