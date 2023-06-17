package os2

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"os2/model"
)

func setRole(ctx context.Context, s logical.Storage, roleEntry *model.RoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/", roleEntry.RoleName())
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
