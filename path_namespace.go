package os2

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/exp/slices"
	"os2/model"
	"strings"
)

func pathNamespace(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "namespace/onboard", //+ framework.GenericNameRegex("namespace"),
			Fields: map[string]*framework.FieldSchema{
				"namespace": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the namespace",
					Required:    true,
				},
				"username": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the user",
					Required:    true,
				},
				"safe_id": {
					Type:        framework.TypeLowerCaseString,
					Description: "CSM v4 SafeId",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathNamespaceOnboard,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathNamespaceOnboard,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathNamespaceDelete,
				},
			},
		},
		{
			Pattern: "namespace/migrate",
			Fields: map[string]*framework.FieldSchema{
				"namespace": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the namespace",
					Required:    true,
				},
				"safe_id": {
					Type:        framework.TypeLowerCaseString,
					Description: "CSM v4 SafeId",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathNamespaceMigrate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathNamespaceMigrate,
				},
			},
		},
		{
			Pattern: "namespace/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathNamespacesList,
				},
			},
		},
	}
}

func (b *backend) pathNamespaceMigrate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	namespace, okName := data.GetOk("namespace")
	safeId, okSafe := data.GetOk("safe_id")
	if !okName || !okSafe {
		return logical.ErrorResponse("fields namespace and safe_id are required"), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	roles, err := client.migrateNamespace(namespace.(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	for i, r := range roles {
		roles[i].Name = safeId.(string) + "_" + r.Username
	}
	// store the roles
	for _, role := range roles {
		if err := setRole(ctx, req.Storage, role); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"role_names": model.ToResponseData(roles),
		}}
	return resp, nil
}

func (b *backend) pathNamespaceOnboard(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	namespace, okName := data.GetOk("namespace")
	username, okUser := data.GetOk("username")
	safeId, okSafe := data.GetOk("safe_id")
	if !okName || !okUser || !okSafe {
		return logical.ErrorResponse("fields namespace, username and safe_id are required"), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role, err := client.onboardNamespace(namespace.(string), username.(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role.Name = safeId.(string) + "_" + role.Username
	if err := setRole(ctx, req.Storage, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"role_name": role.Name,
		}}
	return resp, nil
}

func (b *backend) pathNamespacesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	var dedup []string
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	for _, entry := range entries {
		ns, _, _ := strings.Cut(entry, "_")
		if !slices.Contains(dedup, ns) {
			dedup = append(dedup, ns)
		}
	}
	return logical.ListResponse(dedup), nil
}

func (b *backend) pathNamespaceDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ns := data.Get("namespace").(string)
	// 1. delete all roles
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	for _, role := range roles {
		if strings.HasPrefix(role, ns+"_") {
			err = req.Storage.Delete(ctx, "role/"+role)
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}
		}
	}
	// 2. delete ns in ECS
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := client.deleteNamespace(ns); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

func (b *backend) pathNamespaceUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("namespace can't be updated")
	return resp, nil
}
