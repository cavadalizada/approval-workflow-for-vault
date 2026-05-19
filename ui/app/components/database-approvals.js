/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

/**
 * @module DatabaseApprovals
 * Admin view that lists pending credential approval requests for a database backend
 * and allows approvers to approve or deny them.
 *
 * @example
 * ```hbs
 * <DatabaseApprovals @backendPath="database" />
 * ```
 * @param {string} backendPath - The database mount path (e.g. "database").
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class DatabaseApprovals extends Component {
  @service store;

  /** Array of request detail objects fetched from the backend. */
  @tracked requests = [];

  /** True while the initial list fetch is in flight. */
  @tracked isLoading = false;

  /** Non-null when a fetch/action error occurs. */
  @tracked fetchError = null;

  /** Map of requestId → 'approving' | 'denying' | 'done' for per-row loading state. */
  @tracked actionState = {};

  constructor(owner, args) {
    super(owner, args);
    this.loadRequests();
  }

  get adapter() {
    return this.store.adapterFor('database/credential');
  }

  get namespace() {
    return `v1/${this.args.backendPath}`;
  }

  async #apiGet(path) {
    return this.adapter.ajax(`${this.adapter.buildURL()}/${this.args.backendPath}/${path}`, 'GET');
  }

  async #apiPost(path) {
    return this.adapter.ajax(`${this.adapter.buildURL()}/${this.args.backendPath}/${path}`, 'POST', {
      data: {},
    });
  }

  async #apiList(path) {
    return this.adapter.ajax(`${this.adapter.buildURL()}/${this.args.backendPath}/${path}`, 'GET', {
      data: { list: true },
    });
  }

  @action
  async loadRequests() {
    this.isLoading = true;
    this.fetchError = null;
    try {
      const listResp = await this.#apiList('approvals/pending');
      const ids = listResp?.data?.keys ?? [];

      const details = await Promise.all(
        ids.map(async (id) => {
          try {
            const resp = await this.#apiGet(`approvals/pending/${id}`);
            return resp?.data ?? null;
          } catch {
            return null;
          }
        })
      );

      this.requests = details.filter(Boolean);
    } catch (e) {
      this.fetchError = e?.errors?.[0] ?? 'Failed to load approval requests.';
    } finally {
      this.isLoading = false;
    }
  }

  @action
  async approveRequest(requestId) {
    this.actionState = { ...this.actionState, [requestId]: 'approving' };
    try {
      await this.#apiPost(`approvals/approve/${requestId}`);
      this.actionState = { ...this.actionState, [requestId]: 'done' };
      // Refresh the list after a short delay so the user sees the "done" state briefly.
      setTimeout(() => this.loadRequests(), 800);
    } catch (e) {
      this.actionState = { ...this.actionState, [requestId]: null };
      this.fetchError = e?.errors?.[0] ?? `Failed to approve request ${requestId}.`;
    }
  }

  @action
  async denyRequest(requestId) {
    this.actionState = { ...this.actionState, [requestId]: 'denying' };
    try {
      await this.#apiPost(`approvals/deny/${requestId}`);
      this.actionState = { ...this.actionState, [requestId]: 'done' };
      setTimeout(() => this.loadRequests(), 800);
    } catch (e) {
      this.actionState = { ...this.actionState, [requestId]: null };
      this.fetchError = e?.errors?.[0] ?? `Failed to deny request ${requestId}.`;
    }
  }
}
