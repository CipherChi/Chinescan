# Finding deduplication contract

Code finding identity derives from a canonical tuple of normalized `target`, `category`, `rule_id`, and normalized `location`, serialized with stable field ordering and hashed using SHA-256. Do not include volatile timestamps, display prose, severity, scanner identity, or run IDs in the identity. Normalize paths according to their platform semantics. Source evidence is not included in the fingerprint or persisted payload. Other finding categories may define additional tuples when implemented.
