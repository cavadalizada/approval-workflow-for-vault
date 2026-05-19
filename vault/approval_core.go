// Copyright cavadalizada 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
)

// ---------------------------------------------------------------------------
// Storage paths (all written under systemBarrierView/"approvals/")
// ---------------------------------------------------------------------------

const (
	approvalStoragePrefix = "approvals/"

	// Default TTL for a pending request before it expires (1 hour).
	approvalRequestTTL = 1 * time.Hour
	// How long the requester has to fetch the credential after approval (90 minutes).
	// Burn After Reading: the entire PendingRequest is deleted on first fetch.
	approvalCredentialTTL = 90 * time.Minute

	// approvalHistoryTTL is how long resolved approval entries are retained.
	approvalHistoryTTL = 7 * 24 * time.Hour
)

// ---------------------------------------------------------------------------
// Context bypass key
// ---------------------------------------------------------------------------

// ctxKeyApprovalBypass is a context value key used to mark re-injected
// approval-execution requests so the interceptor in handleRequest does not
// trap them a second time.  It intentionally lives in the vault package (not
// the SDK) to prevent external callers from setting it.
type ctxKeyApprovalBypass struct{}

func withApprovalBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyApprovalBypass{}, true)
}

func isApprovalBypass(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyApprovalBypass{}).(bool)
	return v
}

// ---------------------------------------------------------------------------
// Domain structs
// ---------------------------------------------------------------------------

// ApprovalRule defines a policy that intercepts requests whose path matches
// TargetMountPath.  Stored at approvals/config/{rule_id}.
type ApprovalRule struct {
	RuleID              string   `json:"rule_id"`
	Description         string   `json:"description,omitempty"`
	// TargetMountPath supports exact paths ("database/creds/my-role"),
	// trailing-wildcard globs ("database/creds/*"), and bare "*" (all paths).
	TargetMountPath     string   `json:"target_mount_path"`
	AuthorizedApprovers []string `json:"authorized_approvers"` // OIDC entity IDs
	ApprovalsRequired   int      `json:"approvals_required"`   // default 1
	SlackWebhookURL     string   `json:"slack_webhook_url,omitempty"`
	CreatedByEntityID   string   `json:"created_by_entity_id,omitempty"`
	// AllowSelfApproval disables the Separation of Duties check for this rule.
	// Default false. Set true only for testing or explicitly delegated workflows.
	AllowSelfApproval   bool     `json:"allow_self_approval,omitempty"`
}

// PendingRequest is the parked logical.Request awaiting sufficient approvals.
// Stored at approvals/pending/{request_id}.
type PendingRequest struct {
	RequestID   string `json:"request_id"`
	RuleID      string `json:"rule_id"`

	// Saved request fields.  ClientToken is intentionally omitted — it may
	// expire before the approval arrives, and re-execution does not require it.
	OriginalPath        string                 `json:"original_path"`
	OriginalOperation   logical.Operation      `json:"original_operation"`
	OriginalData        map[string]interface{} `json:"original_data"`
	OriginalHeaders     map[string][]string    `json:"original_headers"`
	OriginalMountPoint  string                 `json:"original_mount_point"`

	// Requester identity (captured from live token; outlasts the token itself).
	RequesterEntityID    string `json:"requester_entity_id"`
	RequesterDisplayName string `json:"requester_display_name"`

	// Approval state.
	Approvals []ApprovalRecord `json:"approvals"`
	Status    string           `json:"status"` // "pending" | "approved" | "denied"
	CreatedAt time.Time        `json:"created_at"`
	ExpiresAt time.Time        `json:"expires_at"`

	// Burn After Reading: populated when approval threshold is met.
	// The credential lives here (not in a separate storage path).
	// Fetch deletes the entire entry; CredentialData nil means already retrieved.
	CredentialData map[string]interface{} `json:"credential_data,omitempty"`
	ApprovedAt     time.Time              `json:"approved_at,omitempty"`
	SecretTTL      time.Duration          `json:"secret_ttl,omitempty"`
	SecretMaxTTL   time.Duration          `json:"secret_max_ttl,omitempty"`

	// Justification is the requester-provided reason for the credential request.
	// Sanitized on ingest; stored as plain text; visible to approvers.
	Justification string `json:"justification,omitempty"`
}

// ApprovalRecord captures one approver's vote.
type ApprovalRecord struct {
	ApproverEntityID string    `json:"approver_entity_id"`
	ApprovedAt       time.Time `json:"approved_at"`
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

// approvalStorage returns the barrier view used for all approval data.
func approvalStorage(c *Core) logical.Storage {
	return c.systemBarrierView.SubView(approvalStoragePrefix)
}

func getApprovalRule(ctx context.Context, c *Core, ruleID string) (*ApprovalRule, error) {
	entry, err := approvalStorage(c).Get(ctx, "config/"+ruleID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var rule ApprovalRule
	if err := entry.DecodeJSON(&rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

func putApprovalRule(ctx context.Context, c *Core, rule *ApprovalRule) error {
	entry, err := logical.StorageEntryJSON("config/"+rule.RuleID, rule)
	if err != nil {
		return err
	}
	return approvalStorage(c).Put(ctx, entry)
}

func storePendingRequest(ctx context.Context, c *Core, r *PendingRequest) error {
	entry, err := logical.StorageEntryJSON("pending/"+r.RequestID, r)
	if err != nil {
		return err
	}
	return approvalStorage(c).Put(ctx, entry)
}

func getPendingRequest(ctx context.Context, c *Core, id string) (*PendingRequest, error) {
	entry, err := approvalStorage(c).Get(ctx, "pending/"+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var r PendingRequest
	if err := entry.DecodeJSON(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// sweepPendingRequestsByRule deletes all pending requests whose RuleID matches
// ruleID. Called when a rule is deleted so orphaned requests don't accumulate.
func sweepPendingRequestsByRule(ctx context.Context, c *Core, ruleID string) error {
	storage := approvalStorage(c)
	keys, err := storage.List(ctx, "pending/")
	if err != nil {
		return err
	}
	for _, key := range keys {
		entry, err := storage.Get(ctx, "pending/"+key)
		if err != nil || entry == nil {
			continue
		}
		var r PendingRequest
		if err := entry.DecodeJSON(&r); err != nil {
			continue
		}
		if r.RuleID == ruleID {
			_ = storage.Delete(ctx, "pending/"+key)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

// sanitizeJustification strips control characters, escapes Slack special
// characters, and limits length so the value is safe to store and embed in
// Slack messages without triggering mention injection or link spoofing.
// Allows printable Unicode (≥0x20) except DEL (0x7F).  Max 1000 characters.
func sanitizeJustification(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '&':
			b.WriteString("&amp;")
		case r >= 0x20 && r != 0x7f:
			b.WriteRune(r)
		}
	}
	result := strings.TrimSpace(b.String())
	const maxLen = 1000
	if len(result) > maxLen {
		result = result[:maxLen]
	}
	return result
}

// approvalRuleMatchesPath reports whether rule.TargetMountPath matches reqPath.
// Supported forms:
//   - "*"                 — matches everything
//   - "database/creds/*"  — prefix glob (trailing /* is stripped to prefix)
//   - "database/creds/my-role" — exact match
func approvalRuleMatchesPath(rule *ApprovalRule, reqPath string) bool {
	p := rule.TargetMountPath
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, "/*") {
		prefix := strings.TrimSuffix(p, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	return p == reqPath
}

// ---------------------------------------------------------------------------
// Deduplication guard — one active request per entity per path
// ---------------------------------------------------------------------------

// checkActiveApprovalRequest scans storage for an existing request from the
// same entity for the same exact path and decides whether to block a new one.
//
// Composite key: RequesterEntityID + OriginalPath
//
// Blocking conditions (the "active and unread" test):
//
//	Status == "pending"  AND  ExpiresAt is in the future
//	Status == "approved" AND  CredentialData != nil (not yet fetched)
//	                     AND  ApprovedAt is set
//	                     AND  time.Since(ApprovedAt) < approvalCredentialTTL (90 min)
//
// Stale entries (expired pending, fetched approved, denied) are deleted and
// do NOT block the new request — they are consumed history.
//
// Returns a blocking (*logical.Response, error) when the caller should stop,
// or (nil, nil) when the new request may proceed.
func checkActiveApprovalRequest(ctx context.Context, req *logical.Request, storage logical.Storage) (*logical.Response, error) {
	keys, err := storage.List(ctx, "pending/")
	if err != nil {
		// Non-fatal: if we can't read storage we let the request through rather
		// than silently dropping legitimate requests.
		return nil, nil
	}

	for _, key := range keys {
		entry, err := storage.Get(ctx, "pending/"+key)
		if err != nil || entry == nil {
			continue
		}
		var existing PendingRequest
		if err := entry.DecodeJSON(&existing); err != nil {
			continue
		}

		// Composite-key match: must be same requester AND same exact path.
		// database/creds/readonly and database/creds/admin are distinct events.
		if existing.RequesterEntityID != req.EntityID || existing.OriginalPath != req.Path {
			continue
		}

		switch existing.Status {
		case "pending":
			if time.Now().UTC().Before(existing.ExpiresAt) {
				// Active pending request — block the duplicate.
				inner := logical.ErrorResponse(
					"you already have a pending approval request for %q "+
						"(request ID: %s). "+
						"Please wait for an admin to review it before submitting again.",
					req.Path, existing.RequestID,
				)
				return logical.RespondWithStatusCode(inner, req, http.StatusBadRequest)
			}
			// Pending but TTL has passed — stale. Delete and allow a fresh request.
			_ = storage.Delete(ctx, "pending/"+key)

		case "approved":
			// Active AND unread: credential present + ApprovedAt set + within 90-min window.
			if existing.CredentialData != nil &&
				!existing.ApprovedAt.IsZero() &&
				time.Since(existing.ApprovedAt) < approvalCredentialTTL {

				remaining := approvalCredentialTTL - time.Since(existing.ApprovedAt)
				inner := logical.ErrorResponse(
					"you have an approved, unread credential for %q ready to retrieve "+
						"(request ID: %s, expires in %d minutes). "+
						"Please visit the 'My Requests' tab to view it before requesting a new one.",
					req.Path, existing.RequestID, int(remaining.Minutes()),
				)
				return logical.RespondWithStatusCode(inner, req, http.StatusBadRequest)
			}
			// Fetched (CredentialData nil) or 90-min window expired — consumed history.
			// Delete the stale entry so it doesn't accumulate, then allow a fresh request.
			_ = storage.Delete(ctx, "pending/"+key)

		case "denied":
			// Denied requests never block: the user is explicitly allowed to retry.
			// Leave the entry in place for the My Requests audit trail.
		}

		// We matched on composite key. Even if this entry was stale, we only
		// expect at most one active entry per user+path (this guard enforces it).
		// Any additional matches would themselves be stale — the loop cleans them.
	}

	return nil, nil
}

// ---------------------------------------------------------------------------
// Core interceptor — called from handleRequest immediately before doRouting
// ---------------------------------------------------------------------------

// checkNeedsApproval inspects the request against configured ApprovalRules.
// If a matching rule is found the request is parked, a Slack notification is
// fired, and (resp, true, nil) is returned so handleRequest can short-circuit.
// If no rule matches it returns (nil, false, nil) and the caller continues
// normally.
func (c *Core) checkNeedsApproval(ctx context.Context, req *logical.Request, auth *logical.Auth) (*logical.Response, bool, error) {
	// Only intercept user-facing secret reads/writes — never system, auth,
	// token, or cubbyhole paths, and never revoke/rollback operations.
	if strings.HasPrefix(req.Path, "sys/") ||
		strings.HasPrefix(req.Path, "auth/") ||
		strings.HasPrefix(req.Path, "cubbyhole/") ||
		strings.HasPrefix(req.Path, "identity/") {
		return nil, false, nil
	}
	switch req.Operation {
	case logical.ReadOperation, logical.UpdateOperation, logical.CreateOperation:
	default:
		return nil, false, nil
	}

	// Root tokens bypass the approval workflow entirely.
	if auth != nil {
		for _, p := range auth.Policies {
			if p == "root" {
				return nil, false, nil
			}
		}
	}

	storage := approvalStorage(c)
	ruleKeys, err := storage.List(ctx, "config/")
	if err != nil || len(ruleKeys) == 0 {
		return nil, false, err
	}

	var matchedRule *ApprovalRule
	for _, key := range ruleKeys {
		entry, err := storage.Get(ctx, "config/"+key)
		if err != nil || entry == nil {
			continue
		}
		var rule ApprovalRule
		if err := entry.DecodeJSON(&rule); err != nil {
			continue
		}
		if approvalRuleMatchesPath(&rule, req.Path) {
			matchedRule = &rule
			break
		}
	}

	if matchedRule == nil {
		return nil, false, nil
	}

	// Deduplication: one active request per entity per path.
	// Only enforced when the requester has an entity ID (anonymous tokens skip this).
	if req.EntityID != "" {
		blockResp, blockErr := checkActiveApprovalRequest(ctx, req, storage)
		if blockResp != nil || blockErr != nil {
			return blockResp, true, blockErr
		}
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, false, fmt.Errorf("approval: failed to generate request ID: %w", err)
	}

	// Strip auth and operational Vault headers before persisting.
	// X-Vault-Token / Authorization: credential theft on storage read.
	// X-Vault-Wrap-TTL / X-Vault-Wrap-Format: would wrap the re-executed
	//   response, breaking burn-after-read (credential never lands in CredentialData).
	// X-Vault-Namespace: would redirect re-execution to a different namespace.
	// X-Vault-MFA: replaying MFA proofs is meaningless and potentially unsafe.
	blockedHeaders := map[string]bool{
		"X-Vault-Token":       true,
		"Authorization":       true,
		"X-Vault-Wrap-Ttl":    true,
		"X-Vault-Wrap-Format": true,
		"X-Vault-Namespace":   true,
		"X-Vault-Mfa":         true,
	}
	safeHeaders := make(map[string][]string, len(req.Headers))
	for k, v := range req.Headers {
		if !blockedHeaders[http.CanonicalHeaderKey(k)] {
			safeHeaders[k] = v
		}
	}

	// Extract and sanitize the requester-supplied justification.
	justification := ""
	if vals := req.Headers["X-Vault-Justification"]; len(vals) > 0 {
		justification = sanitizeJustification(vals[0])
	}

	now := time.Now().UTC()
	pending := &PendingRequest{
		RequestID:            id,
		RuleID:               matchedRule.RuleID,
		OriginalPath:         req.Path,
		OriginalOperation:    req.Operation,
		OriginalData:         req.Data,
		OriginalHeaders:      safeHeaders,
		OriginalMountPoint:   req.MountPoint,
		RequesterEntityID:    req.EntityID,
		RequesterDisplayName: req.DisplayName,
		Approvals:            []ApprovalRecord{},
		Status:               "pending",
		CreatedAt:            now,
		ExpiresAt:            now.Add(approvalRequestTTL),
		Justification:        justification,
	}

	if err := storePendingRequest(ctx, c, pending); err != nil {
		return nil, false, fmt.Errorf("approval: failed to store pending request: %w", err)
	}

	c.logger.Info("approval: request intercepted",
		"request_id", id,
		"rule_id", matchedRule.RuleID,
		"original_path", req.Path,
		"requester_entity_id", req.EntityID,
		"requester_display_name", req.DisplayName,
		"expires_at", pending.ExpiresAt,
	)

	if matchedRule.SlackWebhookURL != "" {
		// Resolve approver display names before entering the goroutine.
		approverNames := make([]string, 0, len(matchedRule.AuthorizedApprovers))
		for _, entityID := range matchedRule.AuthorizedApprovers {
			if c.identityStore != nil {
				if entity, err := c.identityStore.MemDBEntityByID(entityID, false); err == nil && entity != nil && entity.Name != "" {
					approverNames = append(approverNames, entity.Name)
					continue
				}
			}
			approverNames = append(approverNames, entityID)
		}
		go sendApprovalSlackNotification(matchedRule, pending, approverNames, c.redirectAddr)
	}

	inner := &logical.Response{
		Data: map[string]interface{}{
			"status":     "pending",
			"request_id": id,
			"message":    "Request is pending approval",
		},
	}
	resp, err := logical.RespondWithStatusCode(inner, req, http.StatusAccepted)
	return resp, true, err
}

// ---------------------------------------------------------------------------
// Approval executor — called when threshold is reached
// ---------------------------------------------------------------------------

// executeApprovedRequest re-injects the parked request into the router,
// captures the backend response, and stores the credential inside the
// PendingRequest itself (Burn After Reading — no separate credential path).
// The caller is responsible for persisting the mutated pending entry.
func (c *Core) executeApprovedRequest(ctx context.Context, pending *PendingRequest) error {
	execID, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("approval: failed to generate execution ID: %w", err)
	}

	// Reconstruct a minimal logical.Request from the parked data.
	// DisplayName is preserved so the backend (e.g. database) generates the
	// credential username using the original requester's identity.
	reconstructed := &logical.Request{
		ID:          execID,
		Operation:   pending.OriginalOperation,
		Path:        pending.OriginalPath,
		Data:        pending.OriginalData,
		Headers:     pending.OriginalHeaders,
		EntityID:    pending.RequesterEntityID,
		DisplayName: pending.RequesterDisplayName,
		MountPoint:  pending.OriginalMountPoint,
	}

	// The bypass context prevents the interceptor from re-trapping this call.
	bypassCtx := withApprovalBypass(ctx)

	resp, err := c.doRouting(bypassCtx, reconstructed)
	if err != nil {
		return fmt.Errorf("approval: backend execution failed: %w", err)
	}

	// Collect the public-facing credential data and embed it in the pending entry.
	credData := make(map[string]interface{})
	if resp != nil {
		for k, v := range resp.Data {
			credData[k] = v
		}
		if resp.Secret != nil {
			pending.SecretTTL = resp.Secret.TTL
			pending.SecretMaxTTL = resp.Secret.MaxTTL
		}
	}
	pending.CredentialData = credData
	pending.ApprovedAt = time.Now().UTC()

	return storePendingRequest(ctx, c, pending)
}

// ---------------------------------------------------------------------------
// History storage — 7-day audit trail of resolved requests
// ---------------------------------------------------------------------------

// ApprovalHistoryEntry is a lightweight audit record written when a request
// reaches a terminal state.  Stored at approvals/history/{request_id}.
// Purged on read after HistoryExpiresAt (7 days from ResolvedAt).
type ApprovalHistoryEntry struct {
	RequestID            string    `json:"request_id"`
	RuleID               string    `json:"rule_id"`
	OriginalPath         string    `json:"original_path"`
	RequesterEntityID    string    `json:"requester_entity_id"`
	RequesterDisplayName string    `json:"requester_display_name"`
	Justification        string    `json:"justification,omitempty"`
	// Status: "retrieved" (approved+fetched) | "denied" | "expired"
	Status               string    `json:"status"`
	CreatedAt            time.Time `json:"created_at"`
	ResolvedAt           time.Time `json:"resolved_at"`
	ResolvedBy           string    `json:"resolved_by,omitempty"`
	ResolvedByName       string    `json:"resolved_by_name,omitempty"`
	HistoryExpiresAt     time.Time `json:"history_expires_at"`
}

func storeHistoryEntry(ctx context.Context, c *Core, h *ApprovalHistoryEntry) error {
	entry, err := logical.StorageEntryJSON("history/"+h.RequestID, h)
	if err != nil {
		return err
	}
	return approvalStorage(c).Put(ctx, entry)
}

// listAllHistoryEntries returns all entries not yet past HistoryExpiresAt,
// purging stale ones on the fly.
func listAllHistoryEntries(ctx context.Context, c *Core) ([]*ApprovalHistoryEntry, error) {
	storage := approvalStorage(c)
	keys, err := storage.List(ctx, "history/")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	results := make([]*ApprovalHistoryEntry, 0, len(keys))
	for _, key := range keys {
		raw, err := storage.Get(ctx, "history/"+key)
		if err != nil || raw == nil {
			continue
		}
		var h ApprovalHistoryEntry
		if err := raw.DecodeJSON(&h); err != nil {
			continue
		}
		if now.After(h.HistoryExpiresAt) {
			// Stale — purge and skip.
			_ = storage.Delete(ctx, "history/"+key)
			continue
		}
		results = append(results, &h)
	}
	return results, nil
}

// listHistoryEntriesForUser returns entries where RequesterEntityID == entityID.
func listHistoryEntriesForUser(ctx context.Context, c *Core, entityID string) ([]*ApprovalHistoryEntry, error) {
	all, err := listAllHistoryEntries(ctx, c)
	if err != nil {
		return nil, err
	}
	filtered := make([]*ApprovalHistoryEntry, 0, len(all))
	for _, h := range all {
		if h.RequesterEntityID == entityID {
			filtered = append(filtered, h)
		}
	}
	return filtered, nil
}

// ---------------------------------------------------------------------------
// Slack notification (fire-and-forget goroutine)
// ---------------------------------------------------------------------------

type approvalSlackPayload struct {
	Text string `json:"text"`
}

// sendApprovalSlackNotification posts a Slack message to the rule's webhook URL.
// Designed to be called inside a goroutine; errors are discarded silently.
// approverNames is a resolved list of approver display names (or entity IDs as fallback).
// vaultAddr is the Vault server's advertised address used to build the UI link.
func sendApprovalSlackNotification(rule *ApprovalRule, r *PendingRequest, approverNames []string, vaultAddr string) {
	approvalsText := "1 approval required"
	if rule.ApprovalsRequired > 1 {
		approvalsText = fmt.Sprintf("%d approvals required", rule.ApprovalsRequired)
	}

	justificationLine := ""
	if r.Justification != "" {
		justificationLine = fmt.Sprintf("*Justification:* \"%s\"\n", r.Justification)
	}

	approversLine := ""
	if len(approverNames) > 0 {
		short := make([]string, len(approverNames))
		for i, name := range approverNames {
			if idx := strings.Index(name, "@"); idx > 0 {
				short[i] = name[:idx]
			} else {
				short[i] = name
			}
		}
		approversLine = fmt.Sprintf("*Authorized approvers:* %s\n", strings.Join(short, ", "))
	}

	vaultLink := ""
	if vaultAddr != "" {
		vaultLink = fmt.Sprintf("\n<%s/ui/vault/access/approvals/requests|Review in Vault UI>", vaultAddr)
	}

	msg := approvalSlackPayload{
		Text: fmt.Sprintf(
			"<!here> *[Vault] Credential Request Pending Approval*\n"+
				"*Requester:* %s\n"+
				"%s"+ // justification (empty string if not provided)
				"*Path:* `%s`\n"+
				"*Rule:* `%s`\n"+
				"*Request ID:* `%s`\n"+
				"*Requires:* %s\n"+
				"%s"+ // approvers (empty string if none)
				"*Expires:* %s\n\n"+
				"To approve:  `vault write sys/approvals/approve/%s`\n"+
				"To deny:     `vault write sys/approvals/deny/%s`"+
				"%s", // vault UI link
			r.RequesterDisplayName,
			justificationLine,
			r.OriginalPath,
			rule.RuleID,
			r.RequestID,
			approvalsText,
			approversLine,
			r.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			r.RequestID,
			r.RequestID,
			vaultLink,
		),
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return
	}

	resp, err := http.Post(rule.SlackWebhookURL, "application/json", bytes.NewReader(body)) //nolint:gosec
	if err != nil {
		return
	}
	resp.Body.Close()
}
