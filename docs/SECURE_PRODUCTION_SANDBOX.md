# Secure production scanning without Docker on a developer laptop

## Decision and trust boundary

RepoLens currently **refuses acquisition and external scanners in production**.
This file defines the real host controls necessary to replace that temporary
block. The controls **are not deployed** by adding this document. Do not
change the predicates in `acquisition_boundary_available()` or
`external_scanner_execution_allowed()` to return true until independently
enforced isolation is connected to **every** Git and scanner subprocess.

A Linux server/VM and an operating-system-trusted sandbox broker are the
deployment boundary. A developer laptop needs no Docker; GitHub CI may use
its own hosted containers for tests. Application requests must never have
permission to edit sandbox security policies.

## Separate privileged boundary

- Run the API and database client as a non-root account without mount, net
  admin, or cgroup modification privileges. Use a separate privileged
  supervisor with narrowly scoped operations. The supervisor owns
  `/etc/repolens/isolation/` and the enforcement configs; they must be
  root-owned and unwritable by the API and job accounts.
- The supervisor creates an **isolated unit for each job**, never a
  shared sandbox or writable host-level directory. Use Linux namespaces
  (a maintained runtime such as NsJail is one candidate), seccomp, a
  strict read-only runtime filesystem, separate unprivileged UID,
  PID namespace and per-job cgroup v2 for CPU, memory and pids.
- **Disk quota must be enforced by the kernel, not after-the-fact Python
  polling**: create a distinct quota-provisioned per-job filesystem,
  project-quota mount or bounded tmpfs that remains accessible to all
  acquisition steps for that one job. Enforce bytes **and inodes** before
  launching Git. The existing `MAX_GIT_OBJECT_BYTES` checks are
  secondary and do not substitute for quota.
- Use a private network namespace for Git acquisition and have the
  supervisor enforce default-drop egress with a dedicated policy-controlled
  outbound HTTPS proxy permitting only the expected GitHub transport
  endpoint. Block internal/VPC/RFC1918, loopback, metadata, link-local,
  alternate protocols, DNS exfiltration, redirects and arbitrary proxy
  endpoints. Account for GitHub IP changes via the trusted proxy, not
  hardcoded public IP literals.
- For scanners, use a **different no-network policy**, read-only source
  input, a separate small bounded writable scratch area, offline pinned
  scanner binaries and pre-provisioned vulnerability databases. Never
  pass LLM, database, GitHub installation, API or cloud credentials to
  a scanner.
- Force worker exit and cleanup on timeout, cancel, crash, broker outage
  and API restart. Verify the quota project/namespace/cgroup are torn
  down only after descendants have exited. Failed isolation should
  return an explicit unavailable status, not an empty/clean result.

## Contract that must be implemented before unblocking

1. Add a dedicated, host-provisioned isolation broker that accepts a
   **fixed request schema** (job ID, repository URL, branch or immutable
   SHA, budgets). Do not accept arbitrary shell commands from tenants.
   Authenticate the caller using a protected Unix domain socket with
   peer credentials, not an application-set `ISOLATION_ENABLED=true`
   flag.
2. The broker must attest the **actual** per-job quota, network namespace,
   cgroup limits, binary and policy digests before returning a handle.
   Reject unsigned, expired, replayed or non-matching attestation
   evidence. The application must bind it to the exact job and workspace.
3. Route both `clone_repository()` and **snapshot rehydration/fallback**
   through the broker, including fetch, checkout, tree validation and
   commit verification. No raw Git subprocess may bypass this path in
   production. This includes repo work rehydrated during remediation and
   PR analysis.
4. Route each external scanner through the separate offline scanner
   profile. Ensure scanner status is UNAVAILABLE if its isolation cannot
   be attested. Avoid interpreting partial coverage as a clean scan.
5. Change `acquisition_boundary_available()` and
   `external_scanner_execution_allowed()` **only after** broker-side
   enforcement exists, source paths are exhaustively migrated, and
   negative tests prove fail-closed behavior.

## Acceptance tests on a sacrificial, non-production server

Execute these only in a disposable staging environment. Use a dedicated
low-privilege probe account and no production tokens.

- A deliberately over-quota Git pack and multi-file disk fill must fail
  **before** exceeding the assigned filesystem allocation; test byte and
  inode limits separately. Confirm no cross-job reads.
- A fork bomb substitute with a bounded, controlled set of subprocesses,
  memory pressure and CPU saturation must trip their hard kernel cgroup
  limits and leave no orphaned children.
- Try outbound connections to a controlled reachable internal canary,
  cloud metadata emulator and non-GitHub public endpoint. They must be
  denied; a single approved GitHub transport request must succeed.
  **Connection failure to a host that was already unreachable proves
  nothing**. Include redirects and DNS-rebinding attempts.
- Inside the scanner profile, a controlled reachable public HTTP
  canary must be denied, a preloaded scanner must complete, and no
  secrets or privileged filesystem paths may be visible to the job.
- Kill the worker during clone, checkout and analysis, plus restart the
  API and simulate broker outage. No leaked quota project, partial
  results, unsafe retry or durable-work duplication is allowed.
- Validate auth/session, cross-tenant 404 masking, review COMMENT-only
  permissions, no default-branch writes, and production readiness 503
  during isolation outages. Run full CI and staging browser tests.

## Already implemented application-layer protections

The Git helper restricts production transport to HTTPS, rejects Git
redirects and does not inherit host proxy or home-directory credentials.
Cloning retains bounded object monitoring and the scanner subprocess
path already bounds stdout/stderr and process-tree lifetime. These
protections reduce risk but **cannot** provide a hard disk quota or an
egress firewall by themselves.

## Release decision

Until the per-job host isolation service is provisioned and the application
routes *all* remote Git and scanner processes through it, the production
gate **must remain closed**. A green GitHub Actions run confirms only the
tests at that commit, not the existence of this external security service.

Reference: [NsJail](https://github.com/google/nsjail) describes Linux
namespaces, resource limits, seccomp and cgroups; it is a candidate
building block, not a replacement for the complete egress and disk
policy above.
