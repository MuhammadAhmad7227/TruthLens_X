# TruthLens X Release & Operations Runbooks

## Key rotation
1. Generate a new signing key and assign a new key identifier.
2. Publish the public key before issuing new tokens.
3. Keep the previous key only for the configured verification overlap.
4. Revoke active sessions after emergency compromise.

## Integrity mismatch
1. Stop analysis against the affected physical object.
2. Preserve the original hash and custody history.
3. Record an integrity alert.
4. Re-acquire only through the approved evidence process.

## Backup/restore
1. Snapshot PostgreSQL and the private evidence store.
2. Restore into an isolated clean stack.
3. Run the integrity sweep.
4. Verify custody and audit chains before release.

## External AI
External providers remain disabled by default. Enabling requires an audited, expiring admin grant and
an explicit data-egress disclosure.
