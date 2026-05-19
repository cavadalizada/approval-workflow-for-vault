/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { service } from '@ember/service';
import { registerDestructor } from '@ember/destroyable';

const POLL_INTERVAL_MS = 5000;

export default class GenerateCredentialsDatabase extends Component {
  @service store;

  /** Holds the resolved credential once polling succeeds. */
  @tracked resolvedCred = null;

  /** Holds the pending/credential model returned by the initial fetch. */
  @tracked fetchedModel = null;

  /** Error string when polling fails (denied, expired, not found). */
  @tracked pollError = null;

  /** Error object from the initial credential fetch; allows the user to retry. */
  @tracked fetchError = null;

  /** Justification text entered by the user. */
  @tracked justification = '';

  /** True once the user has submitted the justification form (or auto-fetch started). */
  @tracked hasRequested = false;

  #pollTimer = null;

  constructor(owner, args) {
    super(owner, args);
    if (args.model?.status === 'pending' && args.model?.requestId) {
      // Back-compat: pre-loaded pending model — start polling immediately.
      this.hasRequested = true;
      this.#startPolling(args.backendPath, args.model.requestId);
    } else if (!args.requiresApproval) {
      // No approval rule covers this path — skip the form and generate immediately.
      // hasRequested is set synchronously so the justification form is never rendered.
      this.hasRequested = true;
      this.#doFetch('');
    }
    registerDestructor(this, () => this.#stopPolling());
  }

  /** The effective credential: polled result → freshly fetched → or pre-loaded via @model. */
  get model() {
    return this.resolvedCred || this.fetchedModel || this.args.model;
  }

  get isPending() {
    return this.model?.status === 'pending' && !this.pollError;
  }

  /** True while the initial auto-fetch (non-approval path) is in flight. */
  get isLoading() {
    return this.hasRequested && !this.model && !this.fetchError && !this.pollError;
  }

  get errorTitle() {
    return (
      this.fetchError?.errors?.[0] ||
      this.fetchError?.message ||
      this.args.model?.errorTitle ||
      'Something went wrong'
    );
  }

  get breadcrumbs() {
    return [
      {
        label: this.args.backendPath,
        route: 'vault.cluster.secrets.backend.overview',
        model: this.args.backendPath,
      },
      { label: this.args.roleName },
    ];
  }

  get justificationTrimmed() {
    return this.justification.trim();
  }

  @action
  updateJustification(evt) {
    this.justification = evt.target.value;
  }

  @action
  async requestCredentials(evt) {
    evt.preventDefault();
    const j = this.justificationTrimmed;
    if (!j) return;
    await this.#doFetch(j);
  }

  async #doFetch(justification) {
    this.hasRequested = true;
    this.fetchError = null;

    try {
      const result = await this.store.queryRecord('database/credential', {
        backend: this.args.backendPath,
        secret: this.args.roleName,
        roleType: this.args.roleType || '',
        justification,
      });
      this.fetchedModel = result;
      if (result?.status === 'pending' && result?.requestId) {
        this.#startPolling(this.args.backendPath, result.requestId);
      }
    } catch (e) {
      this.fetchError = e;
      this.hasRequested = false;
    }
  }

  #startPolling(backendPath, requestId) {
    const adapter = this.store.adapterFor('approval-request');
    this.#pollTimer = setInterval(async () => {
      try {
        const resp = await adapter.fetchStatus(requestId);
        const status = resp?.data?.status;

        if (status === 'approved') {
          this.resolvedCred = {
            status: 'approved',
            username: resp.data.username,
            password: resp.data.password,
            leaseId: resp.data.lease_id || '',
            leaseDuration: resp.data.lease_duration || 0,
            roleType: 'dynamic',
          };
          this.#stopPolling();
        } else if (status === 'denied') {
          this.pollError = 'Your credential request was denied by an approver.';
          this.#stopPolling();
        } else if (status === 'expired') {
          this.pollError = 'Your credential request expired before it was approved.';
          this.#stopPolling();
        }
        // status === "pending" (HTTP 202): continue polling silently.
      } catch (e) {
        const httpStatus = e.httpStatus;
        if (httpStatus === 404 || httpStatus === 400) {
          this.pollError =
            'Approval request not found — it may have expired or the server was restarted. Please try again.';
          this.#stopPolling();
        } else if (httpStatus === 403) {
          this.pollError = 'Permission denied while checking approval status.';
          this.#stopPolling();
        }
        // 5xx / network errors: keep polling; transient failures should self-heal.
      }
    }, POLL_INTERVAL_MS);
  }

  #stopPolling() {
    if (this.#pollTimer !== null) {
      clearInterval(this.#pollTimer);
      this.#pollTimer = null;
    }
  }

  @action redirectPreviousPage() {
    window.history.back();
  }
}
