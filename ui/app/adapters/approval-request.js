/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  namespace: 'v1/sys',

  pathForType() {
    return 'approvals/pending';
  },

  // Action helpers called directly by components — not Ember Data operations.

  approve(requestId) {
    return this.ajax(`/v1/sys/approvals/approve/${requestId}`, 'POST');
  },

  deny(requestId) {
    return this.ajax(`/v1/sys/approvals/deny/${requestId}`, 'POST');
  },

  // Polls sys/approvals/fetch/:id — called by ApprovalsPendingBanner every ~5s.
  fetchStatus(requestId) {
    return this.ajax(`/v1/sys/approvals/fetch/${requestId}`, 'GET');
  },

  // Checks whether a path is covered by an approval rule.
  // Returns { data: { requires_approval: bool, rule_id?: string } }
  checkRequiresApproval(path) {
    return this.ajax('/v1/sys/approvals/requires-approval', 'GET', { data: { path } });
  },

  // Returns resolved requests from the past 7 days (approvers / root only).
  fetchHistory() {
    return this.ajax('/v1/sys/approvals/history', 'GET');
  },
});
