package os2

import (
	"context"
	"fmt"
	"os2/model"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "username to access dell ecs api",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "username",
						Sensitive: false,
					},
				},
				"password": {
					Type:        framework.TypeString,
					Description: "password to access dell ecs api",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "password",
						Sensitive: true,
					},
				},
				"url": {
					Type:        framework.TypeString,
					Description: "url to access dell ecs api",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "url",
						Sensitive: false,
					},
				},
				"skip_ssl": {
					Type:        framework.TypeBool,
					Description: "whether to skip or not ssl verify when accessing dell ecs api",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "skip_ssl",
						Sensitive: false,
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
			},
			ExistenceCheck:  b.pathExistenceCheck,
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
		{
			Pattern: "config/rotate",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigRotateWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigRotateWrite,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
		},
	}
}

func (b *backend) pathConfigRotateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := GetConfig(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("getting API client", err), nil
	}
	pwd, err := client.rotatePwd(config.Username)
	if err != nil {
		return logical.ErrorResponse(" ECS API rotate", err), nil
	}
	config.Password = pwd
	if err := b.persistConfig(ctx, *config, req.Storage); err != nil {
		return logical.ErrorResponse("storing config", err), nil
	}
	return nil, nil

}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := GetConfig(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"password": "<masked>",
			"url":      config.Url,
			"skip_ssl": config.SkipSsl,
		}}
	return resp, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	username, okUser := data.GetOk("username")
	password, okPwd := data.GetOk("password")
	url, okUrl := data.GetOk("url")
	if !okUser || !okPwd || !okUrl {
		return logical.ErrorResponse("fields username, password and url are required"), nil
	}
	config := model.PluginConfig{
		Username: username.(string),
		Password: password.(string),
		Url:      url.(string),
		SkipSsl:  data.Get("skip_ssl").(bool),
	}
	if err := b.persistConfig(ctx, config, req.Storage); err != nil {
		return logical.ErrorResponse("storing config", err), nil
	}
	return nil, nil
}

func (b *backend) persistConfig(ctx context.Context, config model.PluginConfig, storage logical.Storage) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, &config)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	// reset client so next invocation will pick up config changes
	b.reset()
	return nil
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func GetConfig(ctx context.Context, storage logical.Storage) (*model.PluginConfig, error) {
	entry, err := storage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(model.PluginConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `object-store configuration. Fields: username, password, url and skip_ssl. All fields are written/updated, so give them values!`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The ECS secret backend requires credentials for managing
Access Keys issued to users working with the products API.

You must sign up with a username and password and
specify the HashiCups address for the products API
before using this secrets backend.
`
