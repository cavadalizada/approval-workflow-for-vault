/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { service } from '@ember/service';

const SUPPORTED_DYNAMIC_BACKENDS = ['database', 'ssh', 'aws', 'totp'];

export default Route.extend({
  templateName: 'vault/cluster/secrets/backend/credentials',
  pathHelp: service('path-help'),
  router: service(),
  store: service(),

  beforeModel(transition) {
    const { id: backendPath, type: backendType } = this.modelFor('vault.cluster.secrets.backend');
    // redirect if the backend type does not support credentials
    if (!SUPPORTED_DYNAMIC_BACKENDS.includes(backendType)) {
      return this.router.transitionTo('vault.cluster.secrets.backend.list-root', backendPath);
    }
    // hydrate model if backend type is ssh
    if (backendType === 'ssh') {
      this.pathHelp.hydrateModel('ssh-otp-credential', backendPath);
    }

    // assign back button route
    if (backendType === 'totp') {
      const previousRoute = transition.from?.name ?? 'vault.cluster.secrets.backend.list-root';
      this.set('backRoute', previousRoute);
    }
  },

  async getAwsRole(backend, id) {
    try {
      const role = await this.store.queryRecord('role-aws', { backend, id });
      return role;
    } catch (e) {
      // swallow error, non-essential data
      return;
    }
  },

  async getTotpKey(backend, keyName) {
    try {
      const key = await this.store.queryRecord('totp-key', { id: keyName, backend });
      return key;
    } catch (e) {
      // swallow error, non-essential data
      return;
    }
  },

  async model(params) {
    const role = params.secret;
    const { id: backendPath, type: backendType } = this.modelFor('vault.cluster.secrets.backend');
    const backendData = { backendPath, backendType };
    const roleType = params.roleType;
    let dbCred, awsRole, totpCodePeriod, backRoute;
    if (backendType === 'database') {
      // Check if either the dynamic or static creds path for this role requires approval.
      // Both are checked in parallel; the form is shown if either matches a rule.
      // Errors (permission denied, no rules configured) are swallowed — default to false
      // so that non-human callers and users without sys/ read access are never blocked.
      //
      // When approval IS required we also infer the correct roleType so the adapter uses
      // a single targeted request instead of allSettled (which would fire both /creds/ and
      // /static-creds/ simultaneously, creating two orphaned pending requests in storage).
      let requiresApproval = false;
      let effectiveRoleType = roleType || '';
      try {
        const approvalAdapter = this.store.adapterFor('approval-request');
        const [dynamicCheck, staticCheck] = await Promise.allSettled([
          approvalAdapter.checkRequiresApproval(`${backendPath}/creds/${role}`),
          approvalAdapter.checkRequiresApproval(`${backendPath}/static-creds/${role}`),
        ]);
        const dynamicRequires = dynamicCheck.value?.data?.requires_approval === true;
        const staticRequires = staticCheck.value?.data?.requires_approval === true;
        if (dynamicRequires || staticRequires) {
          requiresApproval = true;
          // Infer role type only when not already known from the URL param.
          // Prefer dynamic; fall back to static only when dynamic path is not covered.
          if (!effectiveRoleType) {
            effectiveRoleType = dynamicRequires ? 'dynamic' : 'static';
          }
        }
      } catch (_) {
        // Intentionally swallowed — see comment above.
      }
      return { ...backendData, roleName: role, roleType: effectiveRoleType, dbCred: null, requiresApproval };
    } else if (backendType === 'aws') {
      awsRole = await this.getAwsRole(backendPath, role);
    } else if (backendType === 'totp') {
      totpCodePeriod = (await this.getTotpKey(backendPath, role))?.period ?? 30;
      backRoute = this.backRoute;
      return { ...backendData, keyName: role, totpCodePeriod, backRoute };
    }

    return {
      ...backendData,
      roleName: role,
      roleType,
      dbCred,
      awsRoleType: awsRole?.credentialType,
    };
  },

  resetController(controller) {
    controller.reset();
  },

  actions: {
    willTransition() {
      // we do not want to save any of the credential information in the store.
      // once the user navigates away from this page, remove all credential info.
      this.store.unloadAll('database/credential');
    },
  },
});
