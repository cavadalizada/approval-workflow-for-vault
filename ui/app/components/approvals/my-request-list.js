/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';

export default class ApprovalsMyRequestListComponent extends Component {
  @service store;
  @service flashMessages;

  // requestId => 'fetching' | null
  @tracked fetchingState = {};

  // requestId => { data: {}, warning: string }
  @tracked revealedSecrets = {};

  get pendingRequests() {
    return (this.args.requests || []).filter((r) => r.status === 'pending');
  }

  get approvedRequests() {
    return (this.args.requests || []).filter((r) => r.status === 'approved');
  }

  get resolvedRequests() {
    return (this.args.requests || []).filter(
      (r) => r.status !== 'pending' && r.status !== 'approved'
    );
  }

  #adapter() {
    return this.store.adapterFor('approval-request');
  }

  @action
  async revealSecret(request) {
    this.fetchingState = { ...this.fetchingState, [request.id]: 'fetching' };
    try {
      const resp = await this.#adapter().fetchStatus(request.id);
      const data = resp?.data ?? {};

      // Strip envelope fields; keep only the actual credential key/value pairs.
      // eslint-disable-next-line no-unused-vars
      const { status, request_id, lease_duration, lease_max_duration, ...creds } = data;

      this.revealedSecrets = {
        ...this.revealedSecrets,
        [request.id]: {
          requestId: request.id,
          path: request.originalPath,
          data: creds,
          leaseDuration: lease_duration ?? null,
          warning:
            'This credential will not be shown again. Copy it now — it has been permanently deleted from Vault.',
        },
      };

      // Do NOT call onRefresh here — the burn-after-read has already deleted the
      // entry from Vault storage. Refreshing now would remove it from approvedRequests
      // and hide the revealed credential before the user can copy it.
      // The user can refresh manually after dismissing the secret.
    } catch (e) {
      const msg = e.errors?.join(', ') || e.message || 'Unknown error';
      this.flashMessages.danger(`Fetch failed: ${msg}`);
    } finally {
      this.fetchingState = { ...this.fetchingState, [request.id]: null };
    }
  }

  @action
  dismissSecret(requestId) {
    const next = { ...this.revealedSecrets };
    delete next[requestId];
    this.revealedSecrets = next;
  }
}
