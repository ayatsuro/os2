package os2

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
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
	if !okNs || !okUsername {
		resp := logical.ErrorResponse("both fields username and namespace are required")
		return resp, nil
	}
	username := usernameI.(string)
	namespace := namespaceI.(string)
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	// check role doesn't exists
	found, err := b.checkRoleExist(ctx, req.Storage, namespace+"_"+username+"_")
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
	if err := setRole(ctx, req.Storage, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"message":       "iam user onboarded",
			"username":      role.Username,
			"access_key_id": role.AccessKeyId,
		}}
	return resp, nil

}

func (b *backend) checkRoleExist(ctx context.Context, storage logical.Storage, prefix string) (bool, error) {
	roles, err := storage.List(ctx, "role/")
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if strings.HasPrefix(role, prefix) {
			return true, nil
		}
	}
	return false, nil
}
