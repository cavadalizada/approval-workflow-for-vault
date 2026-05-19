// Copyright cavadalizada 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// approvalPaths returns the []*framework.Path slice that is registered on the
// system backend.  All paths live under sys/approvals/…
//
// ACL surface (two-layer model):
//
//   Layer 1 — Vault's native ACL engine (PathsSpecial.Root + operation callbacks):
//     - approvals/config/*  — Root list → requires sudo capability in the policy
//     - approvals/pending/* — Root list → requires sudo capability in the policy
//     - approvals/approve/* — UpdateOperation callback → requires update capability
//     - approvals/deny/*    — UpdateOperation callback → requires update capability
//     - approvals/fetch/*   — ReadOperation callback  → requires read capability
//
//   Layer 2 — runtime identity checks inside each handler (defence-in-depth):
//     - approve/deny: req.EntityID must appear in rule.AuthorizedApprovers
//     - fetch:        req.EntityID must match pending.RequesterEntityID
//
// Even a token that passes Layer 1 (has the right policy capability) is rejected
// by Layer 2 if it is not the correct identity for that specific request.
func (b *SystemBackend) approvalPaths() []*framework.Path {
	uuidPattern := `(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`
	ruleIDPattern := `(?P<rule_id>[a-zA-Z0-9_\-]+)`

	return []*framework.Path{
		// ------------------------------------------------------------------ //
		// Rule management (CRUD)
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/config/" + ruleIDPattern,
			Fields: map[string]*framework.FieldSchema{
				"rule_id": {
					Type:        framework.TypeString,
					Description: "Unique identifier for this approval rule.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Human-readable description.",
				},
				"target_mount_path": {
					Type:        framework.TypeString,
					Description: `Path to intercept. Supports exact match, trailing-wildcard glob ("database/creds/*"), or bare "*" for all.`,
				},
				"authorized_approvers": {
					Type:        framework.TypeStringSlice,
					Description: "List of Vault entity IDs (from OIDC) that may approve requests.",
				},
				"approvals_required": {
					Type:        framework.TypeInt,
					Description: "Number of distinct approvals required before execution. Default: 1.",
					Default:     1,
				},
				"slack_webhook_url": {
					Type:        framework.TypeString,
					Description: "Slack incoming webhook URL for approval notifications.",
				},
				"allow_self_approval": {
					Type:        framework.TypeBool,
					Description: "If true, the requester may approve their own request. Default false (Separation of Duties enforced).",
					Default:     false,
				},
			},
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				ruleID := data.Get("rule_id").(string)
				entry, err := approvalStorage(b.Core).Get(ctx, "config/"+ruleID)
				if err != nil {
					return false, err
				}
				return entry != nil, nil
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.handleApprovalRuleRead(),
				logical.UpdateOperation: b.handleApprovalRuleWrite(),
				logical.CreateOperation: b.handleApprovalRuleWrite(),
				logical.DeleteOperation: b.handleApprovalRuleDelete(),
			},
			HelpSynopsis:    "Create, read, update, or delete an approval rule.",
			HelpDescription: "Approval rules define which paths require human approval before a request is dispatched to the backend plugin.",
		},

		// ------------------------------------------------------------------ //
		// Rule list
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/config/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.handleApprovalRuleList(),
			},
			HelpSynopsis:    "List all configured approval rule IDs.",
			HelpDescription: "Returns the list of rule IDs registered in the approval policy engine.",
		},

		// ------------------------------------------------------------------ //
		// Pending request — read (admin or requester can read their own)
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/pending/" + uuidPattern,
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Request UUID.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalPendingRead(),
			},
			HelpSynopsis:    "Read the status of a pending approval request.",
			HelpDescription: "Returns requester identity, target path, approval state, and expiry.",
		},

		// ------------------------------------------------------------------ //
		// Pending list (admin)
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/pending/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.handleApprovalPendingList(),
			},
			HelpSynopsis:    "List IDs of all pending approval requests.",
			HelpDescription: "Returns UUIDs of requests currently in the 'pending' state.",
		},

		// ------------------------------------------------------------------ //
		// Approve
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/approve/" + uuidPattern,
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Request UUID to approve.",
				},
			},
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				id := data.Get("id").(string)
				entry, err := approvalStorage(b.Core).Get(ctx, "pending/"+id)
				if err != nil {
					return false, err
				}
				return entry != nil, nil
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.handleApprovalApprove(),
			},
			HelpSynopsis:    "Approve a pending request.",
			HelpDescription: "Records the caller's approval vote. If the ApprovalsRequired threshold is met the backend request is executed and the credential is stored for retrieval.",
		},

		// ------------------------------------------------------------------ //
		// Deny
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/deny/" + uuidPattern,
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Request UUID to deny.",
				},
			},
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				id := data.Get("id").(string)
				entry, err := approvalStorage(b.Core).Get(ctx, "pending/"+id)
				if err != nil {
					return false, err
				}
				return entry != nil, nil
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.handleApprovalDeny(),
			},
			HelpSynopsis:    "Deny a pending request.",
			HelpDescription: "Marks the request as denied. The requester will see 'denied' status on the next fetch poll.",
		},

		// ------------------------------------------------------------------ //
		// My requests — requester's own request list
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/my-requests",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalMyRequests(),
			},
			HelpSynopsis:    "List the caller's own approval requests.",
			HelpDescription: "Scans all pending requests and returns those whose RequesterEntityID matches the caller. Does not expose other users' requests.",
		},

		// ------------------------------------------------------------------ //
		// Approvable requests — requests the caller is authorised to approve
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/approvable",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalApprovable(),
			},
			HelpSynopsis:    "List requests the caller is authorised to approve.",
			HelpDescription: "Returns pending requests whose rule's authorized_approvers includes the caller's entity ID. Root tokens see all pending requests.",
		},

		// ------------------------------------------------------------------ //
		// Requires-approval check — called by the UI before showing the form
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/requires-approval",
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Vault path to check (e.g. database/creds/my-role).",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalRequiresApproval(),
			},
			HelpSynopsis:    "Check whether a path requires approval before credentials are issued.",
			HelpDescription: "Returns requires_approval: true/false and, when true, the matching rule_id. Accepts path as a query parameter.",
		},

		// ------------------------------------------------------------------ //
		// Fetch (requester polls this endpoint)
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/fetch/" + uuidPattern,
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Request UUID to fetch the credential for.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalFetch(),
			},
			HelpSynopsis:    "Poll for an approved credential.",
			HelpDescription: "Returns 'pending' while awaiting approval, 'denied' if rejected, or the credential data on success. The stored credential is deleted after the first successful read.",
		},

		// ------------------------------------------------------------------ //
		// History (resolved requests — 7-day audit trail)
		// ------------------------------------------------------------------ //
		{
			Pattern: "approvals/history",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleApprovalHistory(),
			},
			HelpSynopsis:    "List resolved approval requests from the past 7 days.",
			HelpDescription: "Returns all resolved requests (retrieved/denied/expired) from the past 7 days. Root tokens and authorized approvers only.",
		},
	}
}

// ---------------------------------------------------------------------------
// Rule handlers
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalRuleList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		keys, err := approvalStorage(b.Core).List(ctx, "config/")
		if err != nil {
			return nil, err
		}
		if keys == nil {
			keys = []string{}
		}
		return &logical.Response{Data: map[string]interface{}{"keys": keys}}, nil
	}
}

func (b *SystemBackend) handleApprovalRuleRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ruleID := data.Get("rule_id").(string)
		rule, err := getApprovalRule(ctx, b.Core, ruleID)
		if err != nil {
			return nil, err
		}
		if rule == nil {
			return logical.ErrorResponse("no approval rule found with ID %q", ruleID), nil
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"rule_id":              rule.RuleID,
				"description":          rule.Description,
				"target_mount_path":    rule.TargetMountPath,
				"authorized_approvers": rule.AuthorizedApprovers,
				"approvals_required":   rule.ApprovalsRequired,
				"slack_webhook_url":    rule.SlackWebhookURL,
				"created_by_entity_id": rule.CreatedByEntityID,
				"allow_self_approval":  rule.AllowSelfApproval,
			},
		}, nil
	}
}

func (b *SystemBackend) handleApprovalRuleWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ruleID := data.Get("rule_id").(string)
		if ruleID == "" {
			return logical.ErrorResponse("rule_id is required"), nil
		}

		// Load existing rule so we can do a partial update (PATCH-like).
		existing, err := getApprovalRule(ctx, b.Core, ruleID)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			existing = &ApprovalRule{
				RuleID:            ruleID,
				ApprovalsRequired: 1,
				CreatedByEntityID: req.EntityID,
			}
		}

		if v, ok := data.GetOk("description"); ok {
			existing.Description = v.(string)
		}
		if v, ok := data.GetOk("target_mount_path"); ok {
			existing.TargetMountPath = v.(string)
		}
		if v, ok := data.GetOk("authorized_approvers"); ok {
			existing.AuthorizedApprovers = v.([]string)
		}
		if v, ok := data.GetOk("approvals_required"); ok {
			n := v.(int)
			if n < 1 {
				return logical.ErrorResponse("approvals_required must be >= 1"), nil
			}
			existing.ApprovalsRequired = n
		}
		if v, ok := data.GetOk("slack_webhook_url"); ok {
			rawURL := v.(string)
			if rawURL != "" {
				u, parseErr := url.Parse(rawURL)
				if parseErr != nil || u.Scheme != "https" {
					return logical.ErrorResponse("slack_webhook_url must use the https:// scheme"), nil
				}
			}
			existing.SlackWebhookURL = rawURL
		}
		if v, ok := data.GetOk("allow_self_approval"); ok {
			existing.AllowSelfApproval = v.(bool)
		}

		if existing.TargetMountPath == "" {
			return logical.ErrorResponse("target_mount_path is required"), nil
		}
		if len(existing.AuthorizedApprovers) == 0 {
			return logical.ErrorResponse("authorized_approvers must contain at least one entity ID"), nil
		}

		if err := putApprovalRule(ctx, b.Core, existing); err != nil {
			return nil, err
		}
		b.Core.logger.Info("approval: rule created/updated",
			"rule_id", existing.RuleID,
			"target_mount_path", existing.TargetMountPath,
			"approvals_required", existing.ApprovalsRequired,
			"created_by_entity_id", existing.CreatedByEntityID,
		)
		return nil, nil
	}
}

func (b *SystemBackend) handleApprovalRuleDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ruleID := data.Get("rule_id").(string)

		// Cascading delete: sweep all pending requests for this rule so they
		// don't accumulate as orphaned storage entries.
		if err := sweepPendingRequestsByRule(ctx, b.Core, ruleID); err != nil {
			b.Core.logger.Warn("approval: failed to sweep pending requests for deleted rule",
				"rule_id", ruleID, "error", err)
			// Non-fatal: the rule deletion proceeds regardless.
		}

		if err := approvalStorage(b.Core).Delete(ctx, "config/"+ruleID); err != nil {
			return nil, err
		}
		b.Core.logger.Info("approval: rule deleted",
			"rule_id", ruleID,
			"deleted_by_entity_id", req.EntityID,
		)
		return nil, nil
	}
}

// ---------------------------------------------------------------------------
// Pending request handlers
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalPendingList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		// Restrict to root tokens and authorized approvers — regular users must not
		// enumerate other users' request UUIDs.
		if !b.callerIsRoot(ctx, req) {
			if req.EntityID == "" {
				return nil, logical.ErrPermissionDenied
			}
			ruleKeys, err := approvalStorage(b.Core).List(ctx, "config/")
			if err != nil {
				return nil, err
			}
			isApprover := false
			for _, key := range ruleKeys {
				entry, err := approvalStorage(b.Core).Get(ctx, "config/"+key)
				if err != nil || entry == nil {
					continue
				}
				var rule ApprovalRule
				if entry.DecodeJSON(&rule) != nil {
					continue
				}
				if approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
					isApprover = true
					break
				}
			}
			if !isApprover {
				return nil, logical.ErrPermissionDenied
			}
		}

		keys, err := approvalStorage(b.Core).List(ctx, "pending/")
		if err != nil {
			return nil, err
		}
		if keys == nil {
			keys = []string{}
		}
		return &logical.Response{Data: map[string]interface{}{"keys": keys}}, nil
	}
}

func (b *SystemBackend) handleApprovalPendingRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get("id").(string)
		pending, err := getPendingRequest(ctx, b.Core, id)
		if err != nil {
			return nil, err
		}
		if pending == nil {
			return logical.ErrorResponse("no approval request found with ID %q", id), nil
		}

		// Only the requester, an authorised approver for the rule,
		// or a root token may read a pending request.
		if !b.callerIsRoot(ctx, req) {
			isRequester := req.EntityID != "" && req.EntityID == pending.RequesterEntityID
			if !isRequester {
				rule, ruleErr := getApprovalRule(ctx, b.Core, pending.RuleID)
				if ruleErr != nil || rule == nil || !approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
					return nil, logical.ErrPermissionDenied
				}
			}
		}

		// Proactively clean up expired pending-only entries on admin read.
		if pending.Status == "pending" && time.Now().UTC().After(pending.ExpiresAt) {
			_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
			return logical.ErrorResponse("request %q has expired and has been removed", id), nil
		}

		approvalList := make([]map[string]interface{}, 0, len(pending.Approvals))
		for _, a := range pending.Approvals {
			approvalList = append(approvalList, map[string]interface{}{
				"approver_entity_id": a.ApproverEntityID,
				"approved_at":        a.ApprovedAt,
			})
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"request_id":             pending.RequestID,
				"rule_id":                pending.RuleID,
				"original_path":          pending.OriginalPath,
				"original_operation":     string(pending.OriginalOperation),
				"requester_entity_id":    pending.RequesterEntityID,
				"requester_display_name": pending.RequesterDisplayName,
				"status":                 pending.Status,
				"approvals":              approvalList,
				"created_at":             pending.CreatedAt,
				"expires_at":             pending.ExpiresAt,
			},
		}, nil
	}
}

// ---------------------------------------------------------------------------
// Requires-approval check handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalRequiresApproval() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		if path == "" {
			return logical.ErrorResponse("path is required"), nil
		}

		storage := approvalStorage(b.Core)
		ruleKeys, err := storage.List(ctx, "config/")
		if err != nil {
			return nil, err
		}

		for _, key := range ruleKeys {
			entry, err := storage.Get(ctx, "config/"+key)
			if err != nil || entry == nil {
				continue
			}
			var rule ApprovalRule
			if err := entry.DecodeJSON(&rule); err != nil {
				continue
			}
			if approvalRuleMatchesPath(&rule, path) {
				return &logical.Response{
					Data: map[string]interface{}{
						"requires_approval": true,
						"rule_id":           rule.RuleID,
					},
				}, nil
			}
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"requires_approval": false,
			},
		}, nil
	}
}

// ---------------------------------------------------------------------------
// Approve handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalApprove() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get("id").(string)

		pending, err := getPendingRequest(ctx, b.Core, id)
		if err != nil {
			return nil, err
		}
		if pending == nil {
			return logical.ErrorResponse("no approval request found with ID %q", id), nil
		}
		// Concurrency guard: a concurrent goroutine may have already transitioned
		// status away from "pending" (see execution block below).
		if pending.Status != "pending" {
			return logical.ErrorResponse("request %q is not pending (current status: %s)", id, pending.Status), nil
		}

		// TTL enforcement — delete expired entries on access to prevent storage accumulation.
		if time.Now().UTC().After(pending.ExpiresAt) {
			_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
			return logical.ErrorResponse("request %q has expired and has been removed", id), nil
		}

		rule, err := getApprovalRule(ctx, b.Core, pending.RuleID)
		if err != nil {
			return nil, err
		}
		// Lazy cascading delete: rule was removed after request was parked.
		if rule == nil {
			_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
			return logical.ErrorResponse("approval rule %q no longer exists; orphaned request has been removed", pending.RuleID), nil
		}

		// [Layer 2 ACL] Caller must be an authorised approver or a root token.
		if !b.callerIsRoot(ctx, req) && !approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
			return nil, logical.ErrPermissionDenied
		}

		// Separation of Duties: requester cannot approve their own request
		// unless the rule explicitly allows it (allow_self_approval toggle).
		if !b.callerIsRoot(ctx, req) && !rule.AllowSelfApproval &&
			req.EntityID != "" && req.EntityID == pending.RequesterEntityID {
			inner := logical.ErrorResponse("Separation of Duties violation: you cannot approve your own request")
			return logical.RespondWithStatusCode(inner, req, http.StatusForbidden)
		}

		// Prevent the same entity from voting twice.
		for _, a := range pending.Approvals {
			if a.ApproverEntityID == req.EntityID && req.EntityID != "" {
				return logical.ErrorResponse("entity %q has already approved this request", req.EntityID), nil
			}
		}

		pending.Approvals = append(pending.Approvals, ApprovalRecord{
			ApproverEntityID: req.EntityID,
			ApprovedAt:       time.Now().UTC(),
		})

		thresholdMet := len(pending.Approvals) >= rule.ApprovalsRequired

		if thresholdMet {
			// Write "approved" to storage BEFORE executing so any concurrent goroutine
			// that reads after this point sees Status != "pending" and exits early,
			// preventing double-execution. The idempotency re-read below covers the
			// narrow window where two goroutines both read "pending" before either wrote.
			pending.Status = "approved"
			if err := storePendingRequest(ctx, b.Core, pending); err != nil {
				return nil, err
			}

			// Re-read from storage to catch a concurrent goroutine that also reached
			// threshold and already wrote the credential into the pending entry.
			latestPending, err := getPendingRequest(ctx, b.Core, id)
			if err != nil {
				return nil, err
			}
			if latestPending == nil || latestPending.CredentialData == nil {
				if err := b.Core.executeApprovedRequest(ctx, pending); err != nil {
					b.Core.logger.Error("approval execution failed", "request_id", id, "error", err)
					// Roll back to "pending" so the approver can retry.
					pending.Status = "pending"
					pending.Approvals = pending.Approvals[:len(pending.Approvals)-1]
					_ = storePendingRequest(ctx, b.Core, pending)
					return nil, fmt.Errorf("approval execution failed: %w", err)
				}
			}
			b.Core.logger.Info("approval: threshold met, credential generated",
				"request_id", id,
				"rule_id", pending.RuleID,
				"original_path", pending.OriginalPath,
				"requester_entity_id", pending.RequesterEntityID,
				"approver_entity_id", req.EntityID,
				"approvals_recorded", len(pending.Approvals),
			)
		} else {
			if err := storePendingRequest(ctx, b.Core, pending); err != nil {
				return nil, err
			}
			b.Core.logger.Info("approval: vote recorded",
				"request_id", id,
				"rule_id", pending.RuleID,
				"original_path", pending.OriginalPath,
				"approver_entity_id", req.EntityID,
				"approvals_recorded", len(pending.Approvals),
				"approvals_required", rule.ApprovalsRequired,
			)
		}

		return &logical.Response{Data: map[string]interface{}{
			"status":             pending.Status,
			"request_id":         id,
			"approvals_recorded": len(pending.Approvals),
			"approvals_required": rule.ApprovalsRequired,
			"threshold_met":      thresholdMet,
		}}, nil
	}
}

// ---------------------------------------------------------------------------
// Deny handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalDeny() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get("id").(string)

		pending, err := getPendingRequest(ctx, b.Core, id)
		if err != nil {
			return nil, err
		}
		if pending == nil {
			return logical.ErrorResponse("no approval request found with ID %q", id), nil
		}
		if pending.Status != "pending" {
			return logical.ErrorResponse("request %q is not pending (current status: %s)", id, pending.Status), nil
		}

		// TTL enforcement — clean up expired entries on access.
		if time.Now().UTC().After(pending.ExpiresAt) {
			_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
			return logical.ErrorResponse("request %q has expired and has been removed", id), nil
		}

		rule, err := getApprovalRule(ctx, b.Core, pending.RuleID)
		if err != nil {
			return nil, err
		}
		// Orphaned request — rule deleted after parking.
		if rule == nil {
			_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
			return logical.ErrorResponse("approval rule %q no longer exists; orphaned request has been removed", pending.RuleID), nil
		}
		// A requester may self-withdraw their own request (no SoD on deny).
		// Only authorised approvers or root tokens may deny others' requests.
		// Both entity IDs must be non-empty for self-withdrawal to be recognised —
		// an empty entity ID cannot prove ownership.
		isSelfWithdraw := req.EntityID != "" && req.EntityID == pending.RequesterEntityID
		if !b.callerIsRoot(ctx, req) && !isSelfWithdraw && !approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
			return nil, logical.ErrPermissionDenied
		}

		pending.Status = "denied"
		if err := storePendingRequest(ctx, b.Core, pending); err != nil {
			return nil, err
		}

		b.Core.logger.Info("approval: request denied",
			"request_id", id,
			"rule_id", pending.RuleID,
			"original_path", pending.OriginalPath,
			"requester_entity_id", pending.RequesterEntityID,
			"denied_by_entity_id", req.EntityID,
		)

		// Write history entry for audit trail.
		now := time.Now().UTC()
		resolvedByName := ""
		if req.EntityID != "" && b.Core.identityStore != nil {
			if entity, err := b.Core.identityStore.MemDBEntityByID(req.EntityID, false); err == nil && entity != nil {
				resolvedByName = entity.Name
			}
		}
		histEntry := &ApprovalHistoryEntry{
			RequestID:            pending.RequestID,
			RuleID:               pending.RuleID,
			OriginalPath:         pending.OriginalPath,
			RequesterEntityID:    pending.RequesterEntityID,
			RequesterDisplayName: pending.RequesterDisplayName,
			Justification:        pending.Justification,
			Status:               "denied",
			CreatedAt:            pending.CreatedAt,
			ResolvedAt:           now,
			ResolvedBy:           req.EntityID,
			ResolvedByName:       resolvedByName,
			HistoryExpiresAt:     now.Add(approvalHistoryTTL),
		}
		if err := storeHistoryEntry(ctx, b.Core, histEntry); err != nil {
			b.Core.logger.Warn("approval: failed to store history entry",
				"request_id", id, "error", err)
		}

		return &logical.Response{Data: map[string]interface{}{
			"status":     "denied",
			"request_id": id,
		}}, nil
	}
}

// ---------------------------------------------------------------------------
// Fetch handler — the Ember UI polls this endpoint
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalFetch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get("id").(string)

		pending, err := getPendingRequest(ctx, b.Core, id)
		if err != nil {
			return nil, err
		}
		if pending == nil {
			// Return 404 (not 400) so the polling banner can distinguish
			// "truly gone" from transient errors and stop polling cleanly.
			inner := logical.ErrorResponse(
				"approval request %q not found — it may have expired, been removed, or the server was restarted",
				id,
			)
			return logical.RespondWithStatusCode(inner, req, http.StatusNotFound)
		}

		// Only the original requester may fetch their credential.
		// If the request has no entity ID (made by an entity-less token), only a root
		// token may fetch it — ownership cannot be proven otherwise.
		if pending.RequesterEntityID == "" {
			if !b.callerIsRoot(ctx, req) {
				return nil, logical.ErrPermissionDenied
			}
		} else if req.EntityID != pending.RequesterEntityID {
			return nil, logical.ErrPermissionDenied
		}

		switch pending.Status {
		case "pending":
			// TTL enforcement: delete expired entries so the requester gets a definitive
			// "expired" answer and storage is reclaimed. Primary cleanup path since most
			// unanswered requests are discovered through polling.
			if time.Now().UTC().After(pending.ExpiresAt) {
				_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
				b.Core.logger.Info("approval: pending request expired during poll",
					"request_id", id,
					"rule_id", pending.RuleID,
					"original_path", pending.OriginalPath,
					"requester_entity_id", pending.RequesterEntityID,
					"expired_at", pending.ExpiresAt,
				)
				// Write history entry for expired pending.
				expiredNow := time.Now().UTC()
				expiredHist := &ApprovalHistoryEntry{
					RequestID:            pending.RequestID,
					RuleID:               pending.RuleID,
					OriginalPath:         pending.OriginalPath,
					RequesterEntityID:    pending.RequesterEntityID,
					RequesterDisplayName: pending.RequesterDisplayName,
					Justification:        pending.Justification,
					Status:               "expired",
					CreatedAt:            pending.CreatedAt,
					ResolvedAt:           expiredNow,
					HistoryExpiresAt:     expiredNow.Add(approvalHistoryTTL),
				}
				if err := storeHistoryEntry(ctx, b.Core, expiredHist); err != nil {
					b.Core.logger.Warn("approval: failed to store history entry",
						"request_id", id, "error", err)
				}
				return &logical.Response{
					Data: map[string]interface{}{
						"status":     "expired",
						"request_id": id,
						"message":    "Request has expired and has been removed.",
					},
				}, nil
			}
			// Return 202 Accepted during active polling — avoids server-side error log noise.
			inner := &logical.Response{
				Data: map[string]interface{}{
					"status":             "pending",
					"request_id":         id,
					"approvals_recorded": len(pending.Approvals),
				},
			}
			return logical.RespondWithStatusCode(inner, req, http.StatusAccepted)

		case "denied":
			return &logical.Response{
				Data: map[string]interface{}{
					"status":     "denied",
					"request_id": id,
				},
			}, nil

		case "approved":
			if pending.CredentialData == nil {
				return logical.ErrorResponse("credential for request %q has already been retrieved", id), nil
			}
			// 90-minute Burn After Reading window from approval time.
			if !pending.ApprovedAt.IsZero() && time.Since(pending.ApprovedAt) > approvalCredentialTTL {
				_ = approvalStorage(b.Core).Delete(ctx, "pending/"+id)
				b.Core.logger.Info("approval: approved credential window expired",
					"request_id", id,
					"rule_id", pending.RuleID,
					"original_path", pending.OriginalPath,
					"requester_entity_id", pending.RequesterEntityID,
					"approved_at", pending.ApprovedAt,
				)
				// Determine last approver for history.
				lastApproverID := ""
				lastApproverName := ""
				if n := len(pending.Approvals); n > 0 {
					lastApproverID = pending.Approvals[n-1].ApproverEntityID
					if lastApproverID != "" && b.Core.identityStore != nil {
						if entity, err := b.Core.identityStore.MemDBEntityByID(lastApproverID, false); err == nil && entity != nil {
							lastApproverName = entity.Name
						}
					}
				}
				windowExpiredNow := time.Now().UTC()
				windowExpiredHist := &ApprovalHistoryEntry{
					RequestID:            pending.RequestID,
					RuleID:               pending.RuleID,
					OriginalPath:         pending.OriginalPath,
					RequesterEntityID:    pending.RequesterEntityID,
					RequesterDisplayName: pending.RequesterDisplayName,
					Justification:        pending.Justification,
					Status:               "expired",
					CreatedAt:            pending.CreatedAt,
					ResolvedAt:           windowExpiredNow,
					ResolvedBy:           lastApproverID,
					ResolvedByName:       lastApproverName,
					HistoryExpiresAt:     windowExpiredNow.Add(approvalHistoryTTL),
				}
				if err := storeHistoryEntry(ctx, b.Core, windowExpiredHist); err != nil {
					b.Core.logger.Warn("approval: failed to store history entry",
						"request_id", id, "error", err)
				}
				return logical.ErrorResponse("credential for request %q has expired (90-minute retrieval window passed)", id), nil
			}

			// Capture the credential from the in-memory copy before burning storage.
			credData := make(map[string]interface{}, len(pending.CredentialData))
			for k, v := range pending.CredentialData {
				credData[k] = v
			}
			secretTTL := pending.SecretTTL
			secretMaxTTL := pending.SecretMaxTTL

			// Burn-before-read: nil out CredentialData in storage first so a concurrent
			// fetch sees "already retrieved" rather than the live credential.
			// Vault storage has no CAS, so a narrow TOCTOU window remains, but this
			// eliminates the easy-to-exploit case where a second fetch arrives after
			// the first read but before the delete.
			pending.CredentialData = nil
			_ = storePendingRequest(ctx, b.Core, pending)

			// Delete the entire entry (primary Burn After Reading cleanup).
			if err := approvalStorage(b.Core).Delete(ctx, "pending/"+id); err != nil {
				return nil, err
			}

			b.Core.logger.Info("approval: credential fetched and burned",
				"request_id", id,
				"rule_id", pending.RuleID,
				"original_path", pending.OriginalPath,
				"requester_entity_id", pending.RequesterEntityID,
			)

			// Write history entry for successful retrieval.
			// Use the last approver as ResolvedBy (the one who pushed over threshold).
			lastApproverID := ""
			lastApproverName := ""
			if n := len(pending.Approvals); n > 0 {
				lastApproverID = pending.Approvals[n-1].ApproverEntityID
				if lastApproverID != "" && b.Core.identityStore != nil {
					if entity, err := b.Core.identityStore.MemDBEntityByID(lastApproverID, false); err == nil && entity != nil {
						lastApproverName = entity.Name
					}
				}
			}
			retrievedNow := time.Now().UTC()
			retrievedHist := &ApprovalHistoryEntry{
				RequestID:            pending.RequestID,
				RuleID:               pending.RuleID,
				OriginalPath:         pending.OriginalPath,
				RequesterEntityID:    pending.RequesterEntityID,
				RequesterDisplayName: pending.RequesterDisplayName,
				Justification:        pending.Justification,
				Status:               "retrieved",
				CreatedAt:            pending.CreatedAt,
				ResolvedAt:           retrievedNow,
				ResolvedBy:           lastApproverID,
				ResolvedByName:       lastApproverName,
				HistoryExpiresAt:     retrievedNow.Add(approvalHistoryTTL),
			}
			if err := storeHistoryEntry(ctx, b.Core, retrievedHist); err != nil {
				b.Core.logger.Warn("approval: failed to store history entry",
					"request_id", id, "error", err)
			}

			// Build response with TTL hints so the Ember component can display
			// how long the underlying credential remains valid.
			respData := map[string]interface{}{
				"status":     "approved",
				"request_id": id,
			}
			for k, v := range credData {
				respData[k] = v
			}
			if secretTTL > 0 {
				respData["lease_duration"] = int64(secretTTL.Seconds())
			}
			if secretMaxTTL > 0 {
				respData["lease_max_duration"] = int64(secretMaxTTL.Seconds())
			}

			return &logical.Response{Data: respData}, nil
		}

		return logical.ErrorResponse("unknown status for request %q", id), nil
	}
}

// ---------------------------------------------------------------------------
// Approvable requests handler + My requests handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalApprovable() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		isRoot := b.callerIsRoot(ctx, req)

		if !isRoot && req.EntityID == "" {
			return &logical.Response{
				Warnings: []string{"Token has no entity ID; cannot determine approvable requests. Sign in with OIDC."},
				Data:     map[string]interface{}{"requests": []interface{}{}},
			}, nil
		}

		storage := approvalStorage(b.Core)
		keys, err := storage.List(ctx, "pending/")
		if err != nil {
			return nil, err
		}

		results := make([]map[string]interface{}, 0, len(keys))
		for _, key := range keys {
			entry, err := storage.Get(ctx, "pending/"+key)
			if err != nil || entry == nil {
				continue
			}
			var p PendingRequest
			if err := entry.DecodeJSON(&p); err != nil {
				continue
			}
			if p.Status != "pending" {
				continue
			}
			// Proactively clean up expired entries so they don't surface to approvers.
			if time.Now().UTC().After(p.ExpiresAt) {
				_ = storage.Delete(ctx, "pending/"+key)
				continue
			}
			if !isRoot {
				rule, err := getApprovalRule(ctx, b.Core, p.RuleID)
				if err != nil || rule == nil {
					continue
				}
				if !approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
					continue
				}
			}
			results = append(results, map[string]interface{}{
				"request_id":              p.RequestID,
				"rule_id":                 p.RuleID,
				"original_path":           p.OriginalPath,
				"original_operation":      string(p.OriginalOperation),
				"requester_entity_id":     p.RequesterEntityID,
				"requester_display_name":  p.RequesterDisplayName,
				"justification":           p.Justification,
				"status":                  p.Status,
				"approvals":               p.Approvals,
				"created_at":              p.CreatedAt,
				"expires_at":              p.ExpiresAt,
			})
		}

		return &logical.Response{Data: map[string]interface{}{"requests": results}}, nil
	}
}

// ---------------------------------------------------------------------------
// My requests handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalMyRequests() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		if req.EntityID == "" {
			// Root tokens and tokens issued without an identity entity cannot be
			// matched to specific requests. Return an empty list with a clear
			// explanation instead of an error so the UI renders gracefully.
			return &logical.Response{
				Warnings: []string{
					"This token has no entity ID. My Requests shows requests tied to your OIDC identity. " +
						"Sign in with OIDC to see your personal requests.",
				},
				Data: map[string]interface{}{"requests": []interface{}{}},
			}, nil
		}

		storage := approvalStorage(b.Core)
		keys, err := storage.List(ctx, "pending/")
		if err != nil {
			return nil, err
		}

		results := make([]map[string]interface{}, 0, len(keys))
		for _, key := range keys {
			entry, err := storage.Get(ctx, "pending/"+key)
			if err != nil || entry == nil {
				continue
			}
			var p PendingRequest
			if err := entry.DecodeJSON(&p); err != nil {
				continue
			}
			if p.RequesterEntityID != req.EntityID {
				continue
			}
			// Proactively clean up expired entries — pending past its 1-hour TTL,
			// or approved past the 90-minute credential retrieval window.
			if p.Status == "pending" && time.Now().UTC().After(p.ExpiresAt) {
				_ = storage.Delete(ctx, "pending/"+key)
				continue
			}
			if p.Status == "approved" && !p.ApprovedAt.IsZero() &&
				time.Since(p.ApprovedAt) >= approvalCredentialTTL {
				_ = storage.Delete(ctx, "pending/"+key)
				continue
			}
			row := map[string]interface{}{
				"request_id":    p.RequestID,
				"rule_id":       p.RuleID,
				"original_path": p.OriginalPath,
				"justification": p.Justification,
				"status":        p.Status,
				"created_at":    p.CreatedAt,
				"expires_at":    p.ExpiresAt,
			}
			if !p.ApprovedAt.IsZero() {
				row["approved_at"] = p.ApprovedAt
			}
			results = append(results, row)
		}

		// Append history entries (terminal states) for this user.
		histEntries, err := listHistoryEntriesForUser(ctx, b.Core, req.EntityID)
		if err != nil {
			b.Core.logger.Warn("approval: failed to load history for user",
				"entity_id", req.EntityID, "error", err)
		}
		for _, h := range histEntries {
			histRow := map[string]interface{}{
				"request_id":    h.RequestID,
				"rule_id":       h.RuleID,
				"original_path": h.OriginalPath,
				"justification": h.Justification,
				"status":        h.Status,
				"created_at":    h.CreatedAt,
				"resolved_at":   h.ResolvedAt,
				"resolved_by":   h.ResolvedBy,
				"resolved_by_name": h.ResolvedByName,
			}
			results = append(results, histRow)
		}

		return &logical.Response{Data: map[string]interface{}{"requests": results}}, nil
	}
}

// ---------------------------------------------------------------------------
// History handler
// ---------------------------------------------------------------------------

func (b *SystemBackend) handleApprovalHistory() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		// Only root tokens and callers who are an authorised approver for at least
		// one rule may view the full cross-user history.  Regular users see their
		// own history via sys/approvals/my-requests (which filters by EntityID).
		if !b.callerIsRoot(ctx, req) {
			if req.EntityID == "" {
				return nil, logical.ErrPermissionDenied
			}
			ruleKeys, err := approvalStorage(b.Core).List(ctx, "config/")
			if err != nil {
				return nil, err
			}
			isApprover := false
			for _, key := range ruleKeys {
				entry, err := approvalStorage(b.Core).Get(ctx, "config/"+key)
				if err != nil || entry == nil {
					continue
				}
				var rule ApprovalRule
				if entry.DecodeJSON(&rule) != nil {
					continue
				}
				if approvalEntityIsAuthorized(req.EntityID, rule.AuthorizedApprovers) {
					isApprover = true
					break
				}
			}
			if !isApprover {
				return nil, logical.ErrPermissionDenied
			}
		}

		entries, err := listAllHistoryEntries(ctx, b.Core)
		if err != nil {
			return nil, err
		}

		rows := make([]map[string]interface{}, 0, len(entries))
		for _, h := range entries {
			row := map[string]interface{}{
				"request_id":             h.RequestID,
				"rule_id":                h.RuleID,
				"original_path":          h.OriginalPath,
				"requester_entity_id":    h.RequesterEntityID,
				"requester_display_name": h.RequesterDisplayName,
				"justification":          h.Justification,
				"status":                 h.Status,
				"created_at":             h.CreatedAt,
				"resolved_at":            h.ResolvedAt,
				"resolved_by":            h.ResolvedBy,
				"resolved_by_name":       h.ResolvedByName,
				"history_expires_at":     h.HistoryExpiresAt,
			}
			rows = append(rows, row)
		}

		return &logical.Response{Data: map[string]interface{}{"entries": rows}}, nil
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// callerIsRoot reports whether the request was made by a root token.
// Root tokens bypass the per-entity authorisation check in approve/deny handlers.
func (b *SystemBackend) callerIsRoot(ctx context.Context, req *logical.Request) bool {
	if req.ClientToken == "" {
		return false
	}
	te, err := b.Core.tokenStore.Lookup(ctx, req.ClientToken)
	if err != nil || te == nil {
		return false
	}
	for _, p := range te.Policies {
		if p == "root" {
			return true
		}
	}
	return false
}

func approvalEntityIsAuthorized(entityID string, approvers []string) bool {
	if entityID == "" {
		return false
	}
	for _, a := range approvers {
		if strings.EqualFold(a, entityID) {
			return true
		}
	}
	return false
}

