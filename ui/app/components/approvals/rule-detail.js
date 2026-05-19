/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class ApprovalsRuleDetailComponent extends Component {
  @service router;
  @service flashMessages;

  @tracked showDeleteModal = false;
  @tracked isDeleting = false;

  @action
  openDeleteModal() {
    this.showDeleteModal = true;
  }

  @action
  closeDeleteModal() {
    this.showDeleteModal = false;
  }

  @action
  async deleteRule() {
    this.isDeleting = true;
    const id = this.args.rule.id;
    try {
      await this.args.rule.destroyRecord();
      this.flashMessages.success(`Rule "${id}" deleted.`);
      this.router.transitionTo('vault.cluster.access.approvals');
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Failed to delete rule: ${msg}`);
      this.isDeleting = false;
      this.showDeleteModal = false;
    }
  }
}
