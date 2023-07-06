package os2

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"os2/model"
	"strings"
)

func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"namespace": {
					Type:     framework.TypeLowerCaseString,
					Required: true,
				},
				"safe_id": {
					Type:     framework.TypeLowerCaseString,
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
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
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

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	namespace, okNs := d.GetOk("namespace")
	if !okNs {
		return logical.ErrorResponse("namespace is required"), nil
	}
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if entry != nil {
		return logical.ErrorResponse("role already exists"), nil
	}
	_, username, _ := strings.Cut(roleName, "_")
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil

	}

	role, err := client.createIamUser(namespace.(string), username)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil

	}
	role.Name = roleName
	debug(role)
	if err := setRole(ctx, req.Storage, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"role_name": roleName,
		}}
	return resp, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if entry == nil {
		return logical.ErrorResponse("role not found"), nil
	}

	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

// pathRoleDelete makes a request to Vault storage to delete a role
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if err := client.deleteIamUser(role.Namespace, role.Username); err != nil {
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
