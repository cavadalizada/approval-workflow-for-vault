/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class ApprovalsRuleFormComponent extends Component {
  @service router;
  @service flashMessages;
  @service store;

  @tracked isSaving = false;

  // Form fields tracked locally — avoids mutating the Ember Data model on every
  // keystroke, which would trigger re-renders that destroy focus.
  @tracked _id = this.args.rule.id ?? '';
  @tracked _targetMountPath = this.args.rule.targetMountPath ?? '';
  @tracked _approvalsRequired = this.args.rule.approvalsRequired ?? 1;
  @tracked _slackWebhookUrl = this.args.rule.slackWebhookUrl ?? '';
  @tracked _description = this.args.rule.description ?? '';

  // Approvers textarea state — textarea stays controlled, array kept in sync.
  @tracked approversText = (this.args.rule.authorizedApprovers || []).join('\n');
  _approvers = [...(this.args.rule.authorizedApprovers || [])];

  get isNew() {
    return this.args.rule.isNew;
  }

  @action
  updateField(field, evt) {
    this[`_${field}`] = evt.target.value;
  }

  @action
  updateApprovers(evt) {
    this.approversText = evt.target.value;
    this._approvers = this.approversText
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  @action
  updateNumber(field, evt) {
    const n = parseInt(evt.target.value, 10);
    if (!isNaN(n)) {
      this[`_${field}`] = n;
    }
  }

  @action
  async save(evt) {
    evt.preventDefault();
    this.isSaving = true;
    const isNew = this.args.rule.isNew;
    const ruleId = isNew ? this._id : (this.args.rule.id ?? this._id);

    try {
      const adapter = this.store.adapterFor('approval-rule');
      const data = {
        target_mount_path: this._targetMountPath,
        authorized_approvers: this._approvers,
        approvals_required: this._approvalsRequired,
        slack_webhook_url: this._slackWebhookUrl,
        description: this._description,
      };
      await adapter.ajax(adapter.buildURL('approval-rule', ruleId), 'POST', { data });
      this.flashMessages.success(
        isNew ? `Rule "${ruleId}" created.` : `Rule "${ruleId}" updated.`
      );
      this.router.transitionTo('vault.cluster.access.approvals.rule', ruleId);
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Failed to save rule: ${msg}`);
    } finally {
      this.isSaving = false;
    }
  }

  @action
  cancel() {
    if (this.isNew) {
      this.router.transitionTo('vault.cluster.access.approvals');
    } else {
      this.router.transitionTo('vault.cluster.access.approvals.rule', this.args.rule.id);
    }
  }
}
