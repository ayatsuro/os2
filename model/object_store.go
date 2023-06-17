package model

import "time"

type RoleEntry struct {
	Username        string        `json:"username"`
	AccessKeyId     string        `json:"access_key_id"`
	SecretAccessKey string        `json:"secret_access_key"`
	Namespace       string        `json:"namespace"`
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
}

func (r *RoleEntry) ToResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":           r.TTL.Seconds(),
		"max_ttl":       r.MaxTTL.Seconds(),
		"username":      r.Username,
		"access_key_id": r.AccessKeyId,
	}
	return respData
}

func (r *RoleEntry) RoleName() string {
	return r.Namespace + "_" + r.Username + "_" + r.AccessKeyId

}
