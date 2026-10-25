# Deployment status

ChineScan has no configured production or staging host, image registry, release credentials, or health-check endpoint. The CI container job builds locally for verification and does not publish the image. Production deployment is disabled.

Before adding a deployment workflow, the maintainer must specify the hosting platform, target environment(s), registry and access policy (if needed), deployment identity, health check, rollback procedure, and database backup/migration expectations. Prefer short-lived OIDC credentials where the selected platform supports them. Configure production approval through a protected GitHub environment when available. Do not put credentials in repository files or CI artifacts.

The eventual workflow should promote the exact image digest built and checked by CI, serialize deployments, run a post-deployment health check, and provide a tested rollback path. No deployment or rollback is currently implemented.
