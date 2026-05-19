/**
 * Copyright cavadalizada 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Model, { attr } from '@ember-data/model';

export default class ApprovalRuleModel extends Model {
  // id maps to rule_id via the serializer's primaryKey setting.
  @attr('string') description;
  @attr('string') targetMountPath;
  @attr() authorizedApprovers; // string[]
  @attr('number') approvalsRequired;
  @attr('string') slackWebhookUrl;
  @attr('string') createdByEntityId;
}
