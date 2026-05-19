/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';

export default class ApprovalsRuleRoute extends Route {
  @service store;

  model({ rule_id }) {
    return this.store.findRecord('approval-rule', rule_id);
  }
}
