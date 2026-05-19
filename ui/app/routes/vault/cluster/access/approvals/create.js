/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';

export default class ApprovalsCreateRoute extends Route {
  @service store;

  model() {
    return this.store.createRecord('approval-rule', { approvalsRequired: 1 });
  }

  resetController(controller, isExiting) {
    if (isExiting) {
      const model = controller.model;
      if (model.isNew) {
        model.unloadRecord();
      }
    }
  }
}
