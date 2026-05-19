# Vault — with Human Approval Workflow

This is a fork of [HashiCorp Vault](https://github.com/hashicorp/vault) (BUSL-1.1) that adds a **human approval workflow for database credential requests** — entirely in OSS, no Enterprise license required.

> **New feature additions are on the `release/2.0.0-approvals` branch.**

---

## What's new

Vault OSS has no built-in way to require a human to approve a credential request before it is issued. This fork adds that capability end-to-end: backend engine, REST API, and a full UI built into the existing Vault web interface.

When a user requests a database credential that is covered by an approval rule, their request is **intercepted before it reaches the backend plugin**. An approver reviews it and either approves or denies it. If approved, the credential is generated and stored securely — the requester has 90 minutes to retrieve it once, after which it is permanently deleted.

<!-- GIF: full approval flow walkthrough -->

---

## How it works

### 1. Create an approval rule

An admin creates a rule that defines which Vault paths to intercept, who is allowed to approve requests, and how many approvals are needed.

**Via API:**
```bash
vault write sys/approvals/config/my-rule \
  target_mount_path="database/creds/*" \
  authorized_approvers="<oidc-entity-id-1>,<oidc-entity-id-2>" \
  approvals_required=1 \
  description="All database dynamic credentials require approval" \
  slack_webhook_url="https://hooks.slack.com/services/..."
```

**Via UI:** Access → Approval rules → Create rule

<!-- GIF: creating a rule in the UI -->

`target_mount_path` supports:
- Exact path: `database/creds/readonly`
- Wildcard: `database/creds/*`
- All paths: `*`

---

### 2. User requests a credential

When a user navigates to a database role that is covered by a rule, instead of credentials being issued immediately they are shown a **justification form**. They enter a reason (visible to approvers), submit the request, and the page begins polling automatically.

<!-- GIF: user submitting a request with justification -->

Behind the scenes, the request is intercepted in `handleRequest` before it ever reaches the database plugin. A pending record is stored with the full original request, the requester's identity, and the justification. The user cannot submit a duplicate request while one is already pending.

---

### 3. Approver reviews the request

Approvers see all pending requests under **Access → Pending requests**. Each row shows the requester's name, the target path, the justification, and when the request expires. Approvers can approve or deny with one click.

<!-- GIF: approver reviewing and approving a request -->

**Via API:**
```bash
# Approve
vault write sys/approvals/approve/<request-id>

# Deny
vault write sys/approvals/deny/<request-id>
```

Rules enforce **Separation of Duties** — a requester cannot approve their own request (configurable per rule via `allow_self_approval`). Multi-approver workflows are supported via `approvals_required`.

When the approval threshold is met, Vault **re-executes the original request internally** and stores the generated credential against the pending record.

---

### 4. Requester retrieves the credential

Once approved, the requester's **My requests** page shows a "Reveal Secret" button. Clicking it fetches the credential, displays it once with a copy button, and **immediately deletes it from storage** (burn after read). There is a 90-minute window after approval to retrieve it.

<!-- GIF: requester revealing and copying their credential -->

**Via API:**
```bash
vault read sys/approvals/fetch/<request-id>
```

---

### 5. History

Both the approver view and the requester's My requests page show a **7-day history** of resolved requests (retrieved, denied, expired). Entries are automatically purged after 7 days.

<!-- GIF: history table -->

---

## Slack notifications

When a request is intercepted and a Slack webhook URL is configured on the rule, a notification is sent immediately to the configured channel:

```
@here [Vault] Credential Request Pending Approval
Requester: jane.doe
Justification: "Need read access for incident investigation"
Path: database/creds/readonly
Rule: db-approvals
Request ID: 4cd97bc8-...
Requires: 1 approval
Authorized approvers: john.smith, jane.doe
Expires: 2025-05-19 21:00:00 UTC

To approve:  vault write sys/approvals/approve/4cd97bc8-...
To deny:     vault write sys/approvals/deny/4cd97bc8-...
```

Approver names are resolved from their OIDC display names. Email addresses are shortened to the username part (`john.smith@company.com` → `john.smith`). The channel receives an `@here` ping so approvers are notified immediately.

---

## Security design

- **Server-side enforcement**: the interceptor lives in `handleRequest`, before any plugin dispatch. The UI hint (`requires-approval`) is purely for UX — the backend enforces approval regardless.
- **Burn after read**: credentials are stored in the pending record and deleted on first fetch. A tombstone is written before deletion to close the TOCTOU window.
- **IDOR protection**: only the requester can fetch their own credential; only authorized approvers can read, approve, or deny others' requests.
- **Separation of Duties**: requesters cannot approve their own requests (unless explicitly allowed per rule).
- **Deduplication**: one active pending or unread approved request per user per path.
- **Header safety**: `X-Vault-Token`, `Authorization`, `X-Vault-Wrap-TTL`, `X-Vault-Namespace`, and `X-Vault-MFA` are stripped from stored headers before re-execution.
- **Justification sanitization**: control characters and Slack special characters (`<`, `>`, `&`) are escaped before storage and notification.
- **SSRF protection**: `slack_webhook_url` must use `https://`.

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `sys/approvals/config/:rule_id` | Create or update an approval rule |
| `GET` | `sys/approvals/config/:rule_id` | Read a rule |
| `DELETE` | `sys/approvals/config/:rule_id` | Delete a rule (cascades to pending requests) |
| `LIST` | `sys/approvals/config` | List all rule IDs |
| `GET` | `sys/approvals/requires-approval?path=...` | Check if a path is covered by a rule |
| `GET` | `sys/approvals/my-requests` | List the caller's own requests + 7-day history |
| `GET` | `sys/approvals/approvable` | List requests the caller can approve |
| `POST` | `sys/approvals/approve/:id` | Approve a pending request |
| `POST` | `sys/approvals/deny/:id` | Deny a pending request |
| `GET` | `sys/approvals/fetch/:id` | Poll for / retrieve an approved credential |
| `GET` | `sys/approvals/history` | 7-day resolved history (approvers / root only) |

---

## Building

```bash
# UI
cd ui && npm install && npm run build && cd ..

# Go binary (Linux amd64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "vault ui" -ldflags "-s -w" -o vault .
```

---

## License

This fork inherits the [Business Source License 1.1](LICENSE) from HashiCorp Vault. The approval workflow additions are copyright cavadalizada 2025, also under BUSL-1.1. You may use, modify, and distribute the source freely. You may not use it to offer a competing commercial Vault service.

---

*Based on HashiCorp Vault — https://github.com/hashicorp/vault*
