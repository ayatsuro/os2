package os2

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"os2/model"
)

func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"namespace": {
					Type:     framework.TypeLowerCaseString,
					Required: true,
				},
				"access_key_id": {
					Type:     framework.TypeString,
					Required: true,
				},
				"username": {
					Type:     framework.TypeLowerCaseString,
					Required: true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
		},
	}
}

func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if entry == nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	err = req.Storage.Delete(ctx, "role/"+roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil

	}
	if err := client.deleteAccessKey(role.Namespace, role.Username, role.AccessKey1.AccessKeyId); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*model.Role, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role model.Role
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}
func setRole(ctx context.Context, s logical.Storage, role *model.Role) error {
	entry, err := logical.StorageEntryJSON("role/"+role.Name, role)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}
