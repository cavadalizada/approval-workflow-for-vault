/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';
import { action } from '@ember/object';

export default class ApprovalsRequestsRoute extends Route {
  @service store;

  async model() {
    const adapter = this.store.adapterFor('approval-request');

    const [approvableResult, historyResult] = await Promise.allSettled([
      adapter.ajax('/v1/sys/approvals/approvable', 'GET'),
      adapter.fetchHistory(),
    ]);

    const pending = (approvableResult.value?.data?.requests ?? []).map((d) => ({
      id: d.request_id,
      ruleId: d.rule_id,
      originalPath: d.original_path,
      originalOperation: d.original_operation,
      requesterEntityId: d.requester_entity_id,
      requesterDisplayName: d.requester_display_name,
      justification: d.justification || '',
      status: d.status,
      approvals: d.approvals || [],
      createdAt: d.created_at,
      expiresAt: d.expires_at,
    }));

    const history = (historyResult.value?.data?.entries ?? []).map((h) => ({
      id: h.request_id,
      ruleId: h.rule_id,
      originalPath: h.original_path,
      requesterEntityId: h.requester_entity_id,
      requesterDisplayName: h.requester_display_name,
      justification: h.justification || '',
      status: h.status,
      approvals: [],
      createdAt: h.created_at,
      resolvedAt: h.resolved_at,
      resolvedBy: h.resolved_by_name || h.resolved_by || '',
    }));

    // Pending requests first, then 7-day resolved history.
    return [...pending, ...history];
  }

  @action
  reload() {
    this.refresh();
  }
}
