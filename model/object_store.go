package model

import "time"

type Role struct {
	Name       string        `json:"-"`
	Username   string        `json:"username"`
	AccessKey1 *AccessKey    `json:"access_key_1"`
	AccessKey2 *AccessKey    `json:"access_key_2"`
	Namespace  string        `json:"namespace"`
	TTL        time.Duration `json:"ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
}

func (r *Role) ToResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":             r.TTL.Seconds(),
		"max_ttl":         r.MaxTTL.Seconds(),
		"username":        r.Username,
		"access_key_id_1": r.AccessKey1.AccessKeyId,
		"create_date_1":   r.AccessKey1.CreateDate,
		"access_key_id_2": "n/a",
		"create_date_2":   "n/a",
		"namespace":       r.Namespace,
	}
	if r.AccessKey2 != nil {
		respData["access_key_id_2"] = r.AccessKey2.AccessKeyId
		respData["create_date_2"] = r.AccessKey2.CreateDate
	}
	return respData
}

func (r *Role) NewestKey() (string, string, error) {
	if r.AccessKey2 == nil {
		return r.AccessKey1.AccessKeyId, r.AccessKey1.SecretAccessKey, nil
	}
	d1, err := time.Parse(time.RFC3339, r.AccessKey1.CreateDate)
	if err != nil {
		return "", "", err
	}
	d2, err := time.Parse(time.RFC3339, r.AccessKey2.CreateDate)
	if err != nil {
		return "", "", err
	}
	if d1.After(d2) {
		return r.AccessKey1.AccessKeyId, r.AccessKey1.SecretAccessKey, nil
	}
	return r.AccessKey2.AccessKeyId, r.AccessKey2.SecretAccessKey, nil
}

func ToResponseData(roles []*Role) []string {
	output := make([]string, len(roles))
	for _, role := range roles {
		output = append(output, role.Name)
	}
	return output
}
