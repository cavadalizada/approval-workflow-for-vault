// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	v5 "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredsCreate(b *databaseBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixDatabase,
				OperationVerb:   "generate",
				OperationSuffix: "credentials",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathCredsCreateRead(),
			},

			HelpSynopsis:    pathCredsCreateReadHelpSyn,
			HelpDescription: pathCredsCreateReadHelpDesc,
		},
		{
			Pattern: "static-creds/" + framework.GenericNameRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixDatabase,
				OperationVerb:   "read",
				OperationSuffix: "static-role-credentials",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathStaticCredsRead(),
			},

			HelpSynopsis:    pathStaticCredsReadHelpSyn,
			HelpDescription: pathStaticCredsReadHelpDesc,
		},
	}
}

// credGenResult holds the output of generateDynamicCred before the Vault lease is registered.
type credGenResult struct {
	respData   map[string]interface{}
	internal   map[string]interface{}
	defaultTTL time.Duration
	maxTTL     time.Duration
}

// generateDynamicCred performs the full database user creation for a dynamic role and
// returns the credential data without registering a Vault lease. Callers are responsible
// for wrapping the result in b.Secret(SecretCredsType).Response(...).
//
// It is called by both pathCredsCreateRead (normal flow) and handleApprovalApprove
// (approval flow) so the generation logic lives in one place.
func (b *databaseBackend) generateDynamicCred(ctx context.Context, s logical.Storage, roleName, displayName string) (*credGenResult, error) {
	role, err := b.Role(ctx, s, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("unknown role: %s", roleName)
	}

	dbConfig, err := b.DatabaseConfig(ctx, s, role.DBName)
	if err != nil {
		return nil, err
	}

	if !strutil.StrListContains(dbConfig.AllowedRoles, "*") && !strutil.StrListContainsGlob(dbConfig.AllowedRoles, roleName) {
		return nil, fmt.Errorf("%q is not an allowed role", roleName)
	}

	if !dbConfig.SupportsCredentialType(role.CredentialType) {
		return nil, fmt.Errorf("unsupported credential_type: %q", role.CredentialType.String())
	}

	dbi, err := b.GetConnection(ctx, s, role.DBName)
	if err != nil {
		return nil, err
	}

	dbi.RLock()
	defer dbi.RUnlock()

	ttl, _, err := framework.CalculateTTL(b.System(), 0, role.DefaultTTL, 0, role.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}
	expiration := time.Now().Add(ttl).Add(5 * time.Second)

	newUserReq := v5.NewUserRequest{
		UsernameConfig: v5.UsernameMetadata{
			DisplayName: displayName,
			RoleName:    roleName,
		},
		Statements: v5.Statements{
			Commands: role.Statements.Creation,
		},
		RollbackStatements: v5.Statements{
			Commands: role.Statements.Rollback,
		},
		Expiration: expiration,
	}

	respData := make(map[string]interface{})

	switch role.CredentialType {
	case v5.CredentialTypePassword:
		password, err := b.generateNewPassword(ctx, role.CredentialConfig, dbConfig.PasswordPolicy, dbi)
		if err != nil {
			return nil, err
		}
		newUserReq.CredentialType = v5.CredentialTypePassword
		newUserReq.Password = password

	case v5.CredentialTypeRSAPrivateKey:
		public, private, err := b.generateNewKeypair(role.CredentialConfig)
		if err != nil {
			return nil, err
		}
		newUserReq.CredentialType = v5.CredentialTypeRSAPrivateKey
		newUserReq.PublicKey = public
		respData["rsa_private_key"] = string(private)

	case v5.CredentialTypeClientCertificate:
		generator, err := newClientCertificateGenerator(role.CredentialConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to construct credential generator: %s", err)
		}
		cb, subject, err := generator.generate(b.GetRandomReader(), expiration, newUserReq.UsernameConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate client certificate: %w", err)
		}
		newUserReq.CredentialType = dbplugin.CredentialTypeClientCertificate
		newUserReq.Subject = subject
		respData["client_certificate"] = cb.Certificate
		respData["private_key"] = cb.PrivateKey
		respData["private_key_type"] = cb.PrivateKeyType
	}

	newUserResp, password, err := dbi.database.NewUser(ctx, newUserReq)
	if err != nil {
		b.CloseIfShutdown(dbi, err)
		return nil, err
	}

	respData["username"] = newUserResp.Username
	if role.CredentialType == v5.CredentialTypePassword {
		respData["password"] = password
	}

	internal := map[string]interface{}{
		"username":              newUserResp.Username,
		"role":                  roleName,
		"db_name":               role.DBName,
		"revocation_statements": role.Statements.Revocation,
	}

	return &credGenResult{
		respData:   respData,
		internal:   internal,
		defaultTTL: role.DefaultTTL,
		maxTTL:     role.MaxTTL,
	}, nil
}

func (b *databaseBackend) pathCredsCreateRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (resp *logical.Response, err error) {
		name := data.Get("name").(string)
		modified := false
		defer func() {
			if err == nil && (resp == nil || !resp.IsError()) {
				b.dbEvent(ctx, "creds-create", req.Path, name, modified)
			} else {
				b.dbEvent(ctx, "creds-create-fail", req.Path, name, modified)
			}
		}()

		// Get the role first — needed for both the approval intercept and generation.
		role, err := b.Role(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", name)), nil
		}

		defer func(credType *v5.CredentialType) {
			if err == nil && (resp == nil || !resp.IsError()) {
				recordDatabaseObservation(ctx, b, req, role.DBName, ObservationTypeDatabaseCredentialCreateSuccess,
					AdditionalDatabaseMetadata{key: "role_name", value: name},
					AdditionalDatabaseMetadata{key: "credential_type", value: credType.String()},
					AdditionalDatabaseMetadata{key: "default_ttl", value: role.DefaultTTL.String()},
					AdditionalDatabaseMetadata{key: "max_ttl", value: role.MaxTTL.String()})
			} else {
				b.dbEvent(ctx, "creds-create-fail", req.Path, name, modified)
				recordDatabaseObservation(ctx, b, req, role.DBName, ObservationTypeDatabaseCredentialCreateFail,
					AdditionalDatabaseMetadata{key: "role_name", value: name},
					AdditionalDatabaseMetadata{key: "credential_type", value: credType.String()})
			}
		}(&role.CredentialType)

		result, err := b.generateDynamicCred(ctx, req.Storage, name, req.DisplayName)
		if err != nil {
			return nil, err
		}
		modified = true

		resp = b.Secret(SecretCredsType).Response(result.respData, result.internal)
		resp.Secret.TTL = result.defaultTTL
		resp.Secret.MaxTTL = result.maxTTL
		return resp, nil
	}
}

func (b *databaseBackend) pathStaticCredsRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)

		role, err := b.StaticRole(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse("unknown role: %s", name), nil
		}

		dbConfig, err := b.DatabaseConfig(ctx, req.Storage, role.DBName)
		if err != nil {
			return nil, err
		}

		// If role name isn't in the database's allowed roles, send back a
		// permission denied.
		if !strutil.StrListContains(dbConfig.AllowedRoles, "*") && !strutil.StrListContainsGlob(dbConfig.AllowedRoles, name) {
			return nil, fmt.Errorf("%q is not an allowed role", name)
		}

		respData := map[string]interface{}{
			"username": role.StaticAccount.Username,
			"ttl":      role.StaticAccount.CredentialTTL().Seconds(),
		}
		if !role.StaticAccount.LastVaultRotation.IsZero() {
			respData["last_vault_rotation"] = role.StaticAccount.LastVaultRotation
		}

		if role.StaticAccount.UsesRotationPeriod() {
			respData["rotation_period"] = role.StaticAccount.RotationPeriod.Seconds()
		} else if role.StaticAccount.UsesRotationSchedule() {
			respData["rotation_schedule"] = role.StaticAccount.RotationSchedule
			if role.StaticAccount.RotationWindow.Seconds() != 0 {
				respData["rotation_window"] = role.StaticAccount.RotationWindow.Seconds()
			}

			respData["ttl"] = role.StaticAccount.CredentialTTL().Seconds()
		}

		switch role.CredentialType {
		case v5.CredentialTypePassword:
			respData["password"] = role.StaticAccount.Password
		case v5.CredentialTypeRSAPrivateKey:
			respData["rsa_private_key"] = string(role.StaticAccount.PrivateKey)
		}

		recordDatabaseObservation(ctx, b, req, role.DBName, ObservationTypeDatabaseStaticCredentialRead,
			AdditionalDatabaseMetadata{key: "role_name", value: name},
			AdditionalDatabaseMetadata{key: "credential_type", value: role.CredentialType.String()})

		return &logical.Response{
			Data: respData,
		}, nil
	}
}

const pathCredsCreateReadHelpSyn = `
Request database credentials for a certain role.
`

const pathCredsCreateReadHelpDesc = `
This path reads database credentials for a certain role. The
database credentials will be generated on demand and will be automatically
revoked when the lease is up.
`

const pathStaticCredsReadHelpSyn = `
Request database credentials for a certain static role. These credentials are
rotated periodically.
`

const pathStaticCredsReadHelpDesc = `
This path reads database credentials for a certain static role. The database
credentials are rotated periodically according to their configuration, and will
return the same password until they are rotated.
`
