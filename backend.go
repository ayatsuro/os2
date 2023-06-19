package os2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"sync"
)

var blog hclog.Logger

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *ecsClient
}

var _ logical.Factory = Factory

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	blog = b.Logger()
	return b, nil
}

func newBackend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathNamespace(b),
			pathRole(b),
			pathConfig(b),
			[]*framework.Path{pathCreds(b), pathIamUser(b)}),
		Invalidate: b.invalidate,
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Secrets: []*framework.Secret{
			b.secretAccessKey(),
		},
	}
	return b
}

func (b *backend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *backend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *backend) getClient(ctx context.Context, storage logical.Storage) (*ecsClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}
	b.lock.RUnlock()
	config, err := GetConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("missing plugin config")
	}
	b.lock.Lock()
	unlockFunc = b.lock.Unlock
	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil

}

func debug(obj any) {
	out, _ := json.Marshal(obj)
	blog.Info(string(out))
}
