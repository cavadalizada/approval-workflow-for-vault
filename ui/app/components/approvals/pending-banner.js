/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

/**
 * @module Approvals::PendingBanner
 *
 * Generic polling component rendered whenever a Vault request is intercepted by
 * the OSS approval workflow and returns HTTP 202.
 *
 * @example
 * ```hbs
 * {{#if (eq @model.status "pending")}}
 *   <Approvals::PendingBanner
 *     @requestId={{@model.requestId}}
 *     @onApproved={{this.handleApproved}}
 *   />
 * {{/if}}
 * ```
 *
 * @param {string}   requestId   - The pending request UUID returned in the 202 body.
 * @param {Function} onApproved  - Called with the raw credential data once approved.
 *                                 Signature: (credentialData: object) => void
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { service } from '@ember/service';
import { registerDestructor } from '@ember/destroyable';

const POLL_INTERVAL_MS = 5000;

export default class ApprovalsPendingBannerComponent extends Component {
  @service store;

  /** 'polling' | 'approved' | 'denied' | 'expired' | 'error' */
  @tracked state = 'polling';

  /** Human-readable error message shown when state is 'denied', 'expired', or 'error'. */
  @tracked errorMessage = null;

  #timer = null;

  constructor(owner, args) {
    super(owner, args);
    this.#start();
    registerDestructor(this, () => this.#stop());
  }

  get isPolling() {
    return this.state === 'polling';
  }

  get isDeniedOrExpired() {
    return this.state === 'denied' || this.state === 'expired' || this.state === 'error';
  }

  #adapter() {
    return this.store.adapterFor('approval-request');
  }

  #start() {
    this.#timer = setInterval(() => this.#poll(), POLL_INTERVAL_MS);
  }

  #stop() {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  async #poll() {
    const requestId = this.args.requestId;
    if (!requestId) return;

    try {
      const resp = await this.#adapter().fetchStatus(requestId);
      const status = resp?.data?.status;

      if (status === 'approved') {
        this.#stop();
        this.state = 'approved';
        this.args.onApproved?.(resp.data);
      } else if (status === 'denied') {
        this.#stop();
        this.state = 'denied';
        this.errorMessage = 'Your credential request was denied by an approver.';
      } else if (status === 'expired') {
        this.#stop();
        this.state = 'expired';
        this.errorMessage = 'Your credential request expired before it was approved.';
      }
      // status === 'pending': continue polling silently
    } catch (e) {
      const httpStatus = e.httpStatus;
      if (httpStatus === 403) {
        this.#stop();
        this.state = 'error';
        this.errorMessage = 'Permission denied while checking approval status.';
      } else if (httpStatus === 404 || httpStatus === 400) {
        // 404 = server explicitly says gone; 400 = Vault logical error (e.g. pre-2.0.6 "not found")
        this.#stop();
        this.state = 'expired';
        this.errorMessage =
          'Approval request not found — it may have expired, been denied, or the server was restarted. Please submit a new request.';
      }
      // 5xx / network errors: stay in polling state and retry.
    }
  }
}
