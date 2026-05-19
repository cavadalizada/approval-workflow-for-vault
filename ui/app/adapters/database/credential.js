/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import { allSettled } from 'rsvp';
import ApplicationAdapter from '../application';
import ControlGroupError from 'vault/lib/control-group-error';

export default ApplicationAdapter.extend({
  namespace: 'v1',

  _justificationHeaders(justification) {
    if (!justification) return {};
    // Strip HTTP header-injection characters (CR, LF, NUL) before sending.
    const safe = String(justification)
      .replace(/[\x00-\x1f\x7f]/g, ' ')
      .trim()
      .slice(0, 1000);
    return safe ? { 'X-Vault-Justification': safe } : {};
  },

  _staticCreds(backend, secret, justification) {
    return this.ajax(
      `${this.buildURL()}/${encodeURIComponent(backend)}/static-creds/${encodeURIComponent(secret)}`,
      'GET',
      { headers: this._justificationHeaders(justification) }
    ).then((resp) => ({ ...resp, roleType: 'static' }));
  },

  _dynamicCreds(backend, secret, justification) {
    return this.ajax(
      `${this.buildURL()}/${encodeURIComponent(backend)}/creds/${encodeURIComponent(secret)}`,
      'GET',
      { headers: this._justificationHeaders(justification) }
    ).then((resp) => ({ ...resp, roleType: 'dynamic' }));
  },

  fetchByQuery(store, query) {
    const { backend, secret, justification } = query;
    if (query.roleType === 'static') {
      return this._staticCreds(backend, secret, justification);
    } else if (query.roleType === 'dynamic') {
      return this._dynamicCreds(backend, secret, justification);
    }
    return allSettled([this._staticCreds(backend, secret, justification), this._dynamicCreds(backend, secret, justification)]).then(
      ([staticResp, dynamicResp]) => {
        if (staticResp.state === 'rejected' && dynamicResp.state === 'rejected') {
          if (dynamicResp.reason instanceof ControlGroupError) {
            throw dynamicResp.reason;
          }
          // Prefer the dynamic-creds error: it carries approval workflow context
          // (dedup guards, etc.) that is more actionable than a static-creds miss.
          throw dynamicResp.reason || staticResp.reason;
        }
        // Prefer dynamic when both settled (e.g. both intercepted by an approval rule wildcard).
        // Falls back to static when only the static-creds path succeeded (actual static role).
        return dynamicResp.value || staticResp.value;
      }
    );
  },

  queryRecord(store, type, query) {
    return this.fetchByQuery(store, query);
  },

  rotateRoleCredentials(backend, id) {
    return this.ajax(
      `${this.buildURL()}/${encodeURIComponent(backend)}/rotate-role/${encodeURIComponent(id)}`,
      'POST'
    );
  },
});
