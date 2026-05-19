/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';
import { action } from '@ember/object';

export default class ApprovalsIndexRoute extends Route {
  @service store;

  async model() {
    const adapter = this.store.adapterFor('approval-rule');
    const baseUrl = adapter.buildURL('approval-rule');

    // 1. Get list of rule IDs.
    let keys = [];
    try {
      const listResp = await adapter.ajax(baseUrl, 'GET', { data: { list: true } });
      keys = listResp?.data?.keys ?? [];
    } catch (e) {
      if (e.httpStatus === 404) return [];
      throw e;
    }

    if (keys.length === 0) return [];

    // 2. Fetch full details for each rule so the table can display all columns.
    const results = await Promise.all(
      keys.map(async (key) => {
        try {
          const resp = await adapter.ajax(`${baseUrl}/${key}`, 'GET');
          const d = resp?.data ?? {};
          return {
            id: d.rule_id || key,
            description: d.description,
            targetMountPath: d.target_mount_path,
            authorizedApprovers: d.authorized_approvers || [],
            approvalsRequired: d.approvals_required ?? 1,
            slackWebhookUrl: d.slack_webhook_url,
            createdByEntityId: d.created_by_entity_id,
          };
        } catch {
          return null;
        }
      })
    );

    return results.filter(Boolean);
  }

  @action
  reload() {
    this.refresh();
  }
}
