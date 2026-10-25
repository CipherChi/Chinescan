# Finding deduplication contract

Future finding identity should derive from a canonical tuple of `finding_type`, normalized `target`, normalized `location`, and normalized `evidence_key`, serialized with stable field ordering and hashed using SHA-256. Do not include volatile timestamps, display prose, severity, or scanner run IDs in the identity. Normalize domains case-insensitively and paths according to their platform semantics; preserve meaningful case in arbitrary evidence. Phase 1 requires a non-empty `fingerprint` field but does not yet compute or migrate fingerprints.
