/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class ApprovalsRuleListComponent extends Component {
  @service router;
  @service flashMessages;
  @service store;

  @tracked deleteTarget = null;
  @tracked isDeleting = false;

  @action
  confirmDelete(rule) {
    this.deleteTarget = rule;
  }

  @action
  cancelDelete() {
    this.deleteTarget = null;
  }

  @action
  async deleteRule() {
    this.isDeleting = true;
    const id = this.deleteTarget.id;
    try {
      const adapter = this.store.adapterFor('approval-rule');
      await adapter.ajax(adapter.buildURL('approval-rule', id), 'DELETE');
      this.flashMessages.success(`Approval rule "${id}" deleted.`);
      this.deleteTarget = null;
      this.args.onDelete?.();
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Failed to delete rule "${id}": ${msg}`);
    } finally {
      this.isDeleting = false;
    }
  }
}
