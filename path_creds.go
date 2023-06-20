package os2

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretAccessKeyType = "secretAccessKey"

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
			},
		},
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if role == nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	accessKeyId, secretAccessKey := role.NewestKey()
	resp := b.Secret(secretAccessKeyType).Response(map[string]interface{}{
		"secret_access_key": secretAccessKey,
		"access_key_id":     accessKeyId,
		"namespace":         role.Namespace,
		"username":          role.Username,
	}, map[string]interface{}{
		"secret_access_key": secretAccessKey,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *backend) secretAccessKey() *framework.Secret {
	return &framework.Secret{
		Type: secretAccessKeyType,
		Fields: map[string]*framework.FieldSchema{
			"secret_access_key": {
				Type: framework.TypeString,
			},
		},
	}
}
