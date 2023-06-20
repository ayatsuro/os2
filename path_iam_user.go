package os2

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathIamUser(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "iam-user/" + framework.GenericNameRegex("username"),
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:     framework.TypeString,
				Required: true,
			},
			"namespace": {
				Type:     framework.TypeLowerCaseString,
				Required: true,
			},
			"safe_id": {
				Type:        framework.TypeLowerCaseString,
				Description: "CSM v4 SafeId",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathIamUserWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathIamUserWrite,
			},
		},
	}
}

func (b *backend) pathIamUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	usernameI, okUsername := d.GetOk("username")
	namespaceI, okNs := d.GetOk("namespace")
	safeIdI, okSafe := d.GetOk("safe_id")
	if !okNs || !okUsername || !okSafe {
		resp := logical.ErrorResponse("fields username, namespace and safeId are required")
		return resp, nil
	}
	username := usernameI.(string)
	namespace := namespaceI.(string)
	roleName := safeIdI.(string) + "_" + username
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	// check role doesn't exists
	found, err := b.checkRoleExist(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if found {
		return logical.ErrorResponse("role already exists"), nil
	}
	// onboard
	role, err := client.onboardIamUser(namespace, username, true)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role.Name = roleName
	if err := setRole(ctx, req.Storage, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"role_name": roleName,
		}}
	return resp, nil

}

func (b *backend) checkRoleExist(ctx context.Context, storage logical.Storage, name string) (bool, error) {
	roles, err := storage.List(ctx, "role/")
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role == name {
			return true, nil
		}
	}
	return false, nil
}
