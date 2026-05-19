/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';
import { action } from '@ember/object';

export default class ApprovalsMyRequestsRoute extends Route {
  @service store;

  async model() {
    const adapter = this.store.adapterFor('approval-request');

    try {
      const resp = await adapter.ajax('/v1/sys/approvals/my-requests', 'GET');
      const requests = resp?.data?.requests ?? [];
      return requests.map((r) => ({
        id: r.request_id,
        ruleId: r.rule_id,
        originalPath: r.original_path,
        justification: r.justification || '',
        status: r.status,
        createdAt: r.created_at,
        expiresAt: r.expires_at ?? null,
        approvedAt: r.approved_at ?? null,
        resolvedAt: r.resolved_at ?? null,
        resolvedBy: r.resolved_by_name || r.resolved_by || null,
      }));
    } catch (e) {
      if (e.httpStatus === 404 || e.httpStatus === 403) return [];
      throw e;
    }
  }

  @action
  reload() {
    this.refresh();
  }
}
