/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Model, { attr } from '@ember-data/model';

export default Model.extend({
  username: attr('string'),
  password: attr('string'),
  leaseId: attr('string'),
  leaseDuration: attr('string'),
  lastVaultRotation: attr('string'),
  rotationPeriod: attr('number'),
  ttl: attr('number'),
  roleType: attr('string'),
  // Approval workflow fields
  status: attr('string'),    // "pending" | "denied" | "expired" — set when approval is required
  requestId: attr('string'), // approval request UUID to poll against
});
