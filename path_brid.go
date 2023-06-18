package os2

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathBrid(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "brid" + framework.GenericNameRegex("brid"),
		Fields: map[string]*framework.FieldSchema{
			"brid": {
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
				Callback: b.pathBridWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathBridWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathBridDelete,
			},
		},
	}
}

func (b *backend) pathBridWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	brid, okBrid := d.GetOk("brid")
	namespace, okNs := d.GetOk("namespace")
	if !okNs || !okBrid {
		resp := logical.ErrorResponse("both fields brid and namespace are required")
		return resp, nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role, err := client.onboardBrid(namespace, brid)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
}

func (b *backend) pathBridDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

}
