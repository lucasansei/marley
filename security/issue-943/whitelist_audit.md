# Issue #943 - Whitelist Permission Audit

- Total `@frappe.whitelist` functions: 117
- Unguarded functions: 0
- High risk (allow_guest + unguarded): 0
- Medium risk (authenticated + unguarded): 0

## High risk findings
- None

## Top medium risk findings (first 100)
- None

## Notes
- Heuristic audit via AST. Manual review is required before patch merge.
- Calls to permission wrappers not using `has_permission` naming may need manual validation.
