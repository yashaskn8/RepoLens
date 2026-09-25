# GitHub App integration

RepoLens can optionally receive pull-request events for repositories installed through a GitHub App. The integration is disabled by default. It uses the existing durable change-analysis workflow and existing human-approved review-publication path; it does not publish reviews automatically.

## Enablement and configuration

Set `GITHUB_APP_ENABLED=true` only after creating and configuring a GitHub App. Configure the App ID, OAuth client ID and secret, PEM private key, webhook secret, a random 32-byte state-encryption key encoded as 64 hexadecimal characters, and the public callback URL. The callback must be HTTPS outside local development and must be exactly `<API_V1_STR>/github-app/connect/callback`. `GITHUB_APP_MAX_WEBHOOK_BYTES` and `GITHUB_APP_TOKEN_TIMEOUT_SECONDS` bound webhook intake and GitHub API calls.

Run the normal Alembic migration to add installation, repository, OAuth-state, webhook-delivery, and pull-request-head records. Do not use `Base.metadata.create_all()` as a production migration strategy.

The App needs repository Contents: read for private-repository analysis and Pull requests: read for review previews. Configure Pull requests: write only if the separately enabled, explicitly approved COMMENT-only publication path is required; RepoLens mints a read-scoped token for previews and a write-scoped token only for publication. Metadata: read may be granted by GitHub automatically. Subscribe to the `installation`, `installation_repositories`, and `pull_request` webhook events. Events require JSON content type and are authenticated against the exact raw request body before parsing.

## Connection and authorization

An authenticated RepoLens user starts a short-lived OAuth PKCE transaction. The callback is bound to that user and one-time state; RepoLens exchanges the code to verify which GitHub installations that user can access, then considers only installation records previously observed through signed App webhooks. One unambiguous installation may be bound directly. If multiple installations are available, RepoLens returns a short-lived user-bound selection grant; the user must choose exactly one via the CSRF-protected binding endpoint. The grant stores only a digest and expires after ten minutes. Rebinding an installation already owned by another RepoLens user is rejected. The temporary GitHub user token and OAuth verifier are not persisted. Installing the App alone does not authorize a RepoLens user or enqueue analysis.

The installation and repository IDs from authenticated webhook records are the authorization keys. The current relevant permission grant and its digest are persisted from signed installation events and checked before work is queued or a token is minted. Permission changes invalidate cached credentials; absent or insufficient permission data fails closed. Pull-request analysis is limited to active, user-bound installations and repositories, same-repository (non-fork) pull requests, and exact base/head commit SHAs. Stale webhook updates cannot move a pull-request head backward. A GitHub App installation token is minted for one authorized repository and the smallest permission profile needed for that operation; tokens are held only in a bounded process-local cache and invalidated on installation, permission, repository, or user-binding changes.

Private snapshot fetching uses a temporary Git askpass helper. The installation token is supplied to the fetch process environment, not embedded in the remote URL, command arguments, or Git configuration. The helper and snapshot workspace are removed after use. Public-repository workflows continue to use the existing public snapshot path.

## Webhooks, retries, and review publication

Webhook delivery IDs are idempotent when their authenticated body digest matches; reuse with different bytes is rejected and audited. Processed delivery digests older than 180 days are pruned incrementally in bounded batches as new deliveries arrive. Delivery records and accepted work are committed with the existing durable work-submission/event path. Supported pull-request actions are `opened`, `reopened`, `synchronize`, and `ready_for_review`; closed, draft, merged, and fork-head pull requests are not queued by this integration.

Analysis remains asynchronous. Review publication remains a separate operation: it requires the existing feature configuration, an explicit user approval bound to the exact preview digest, base/head drift validation, and the existing COMMENT-only GitHub write policy. An App-originated analysis does not fall back to a broad personal access token when its installation authority is unavailable.

## Routes

- `POST /api/v1/github-app/connect/start` — authenticated, CSRF-protected PKCE start.
- `GET /api/v1/github-app/connect/callback` — authenticated, one-time OAuth callback and installation binding.
- `POST /api/v1/github-app/connect/bind` — authenticated, CSRF-protected selection from a verified multi-installation grant.
- `GET /api/v1/github-app/connect/installations` — list installations already bound to the current RepoLens user.
- `POST /api/v1/github-app/connect/installations/{installation_id}/disconnect` — remove the current user binding and invalidate cached installation tokens.
- `POST /api/v1/github-app/webhook` — signed, size-bounded GitHub App webhook ingress.

When `GITHUB_APP_ENABLED=false`, these routes are unavailable and existing public-repository behavior is unchanged. The integration does not provide a general private-repository browser, arbitrary GitHub API proxy, write-capable analysis tool, default-branch write, or unattended review publication.

## Operational verification

Before deployment, configure the GitHub App callback and webhook URL, set the secrets using the deployment secret manager, apply migrations, and verify delivery/retry behavior in a non-production App installation. Automated tests use mocked GitHub HTTP responses and do not require a live App or provider credentials. No live GitHub App validation is implied by passing the test suite.
