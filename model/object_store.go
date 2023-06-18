package model

import "time"

type Role struct {
	Username        string        `json:"username"`
	AccessKeyId     string        `json:"access_key_id"`
	SecretAccessKey string        `json:"secret_access_key"`
	Namespace       string        `json:"namespace"`
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
}

func (r *Role) ToResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":           r.TTL.Seconds(),
		"max_ttl":       r.MaxTTL.Seconds(),
		"username":      r.Username,
		"access_key_id": r.AccessKeyId,
		"namespace":     r.Namespace,
	}
	return respData
}

func (r *Role) RoleName() string {
	return r.Namespace + "_" + r.Username + "_" + r.AccessKeyId

}
