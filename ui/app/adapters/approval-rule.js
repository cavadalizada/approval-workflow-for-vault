/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  namespace: 'v1/sys',

  pathForType() {
    return 'approvals/config';
  },

  // Rules use POST for both create and update (Vault convention).
  // The rule_id is always user-supplied and present in the URL.
  createOrUpdate(store, type, snapshot) {
    const ruleId = snapshot.id;
    const serializer = store.serializerFor('approval-rule');
    const data = serializer.serialize(snapshot);
    return this.ajax(this.buildURL('approval-rule', ruleId), 'POST', { data }).then(() => {
      return { data: { ...data, rule_id: ruleId } };
    });
  },

  createRecord() {
    return this.createOrUpdate(...arguments);
  },

  updateRecord() {
    return this.createOrUpdate(...arguments);
  },

  query(store, type) {
    return this.ajax(this.buildURL('approval-rule'), 'GET', { data: { list: true } });
  },
});
