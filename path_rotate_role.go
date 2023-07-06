package os2

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRotateRoleRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRoleRead,
			},
		},
	}
}

func (b *backend) pathRotateRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}
	role.Name = roleName
	oldestKeyId, err := role.OldestKeyId()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil

	}
	if oldestKeyId != "" {
		if err := client.deleteAccessKey(role.Namespace, role.Username, oldestKeyId); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}
	key, err := client.createAccessKey(role.Namespace, role.Username)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role.SetAccessKey(oldestKeyId, key)
	if err := setRole(ctx, req.Storage, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return &logical.Response{
		Data: role.ToResponseData(),
	}, nil
}
