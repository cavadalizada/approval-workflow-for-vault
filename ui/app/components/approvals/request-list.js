/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class ApprovalsRequestListComponent extends Component {
  @service store;
  @service flashMessages;

  // Per-row action state: { [requestId]: 'approving' | 'denying' | null }
  @tracked rowState = {};

  get pendingRequests() {
    return (this.args.requests || []).filter((r) => r.status === 'pending');
  }

  get resolvedRequests() {
    return (this.args.requests || []).filter((r) => r.status !== 'pending');
  }

  #adapter() {
    return this.store.adapterFor('approval-request');
  }

  #setRow(id, state) {
    this.rowState = { ...this.rowState, [id]: state };
  }

  @action
  async approve(request) {
    this.#setRow(request.id, 'approving');
    try {
      await this.#adapter().approve(request.id);
      this.flashMessages.success(`Request ${request.id} approved and credential generated.`);
      this.args.onAction?.();
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Approve failed: ${msg}`);
      this.#setRow(request.id, null);
    }
  }

  @action
  async deny(request) {
    this.#setRow(request.id, 'denying');
    try {
      await this.#adapter().deny(request.id);
      this.flashMessages.info(`Request ${request.id} denied.`);
      this.args.onAction?.();
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Deny failed: ${msg}`);
      this.#setRow(request.id, null);
    }
  }
}
