/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Controller from '@ember/controller';
import { action } from '@ember/object';

export default class ApprovalsIndexController extends Controller {
  @action
  refreshData() {
    this.send('reload');
  }
}
