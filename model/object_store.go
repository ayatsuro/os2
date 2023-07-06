package model

import "time"

type Role struct {
	Name       string        `json:"-"`
	Username   string        `json:"username"`
	AccessKeys []*AccessKey  `json:"access_keys"`
	Namespace  string        `json:"namespace"`
	TTL        time.Duration `json:"ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
}

func (r *Role) ToResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":             r.TTL.Seconds(),
		"max_ttl":         r.MaxTTL.Seconds(),
		"username":        r.Username,
		"access_key_id_1": r.AccessKeys[0].AccessKeyId,
		"create_date_1":   r.AccessKeys[0].CreateDate,
		"access_key_id_2": "n/a",
		"create_date_2":   "n/a",
		"namespace":       r.Namespace,
	}
	if len(r.AccessKeys) == 2 {
		respData["access_key_id_2"] = r.AccessKeys[1].AccessKeyId
		respData["create_date_2"] = r.AccessKeys[1].CreateDate
	}
	return respData
}

func (r *Role) NewestKey() (*AccessKey, error) {
	if len(r.AccessKeys) == 1 {
		return r.AccessKeys[0], nil
	}
	d1, err := time.Parse(time.RFC3339, r.AccessKeys[0].CreateDate)
	if err != nil {
		return nil, err
	}
	d2, err := time.Parse(time.RFC3339, r.AccessKeys[1].CreateDate)
	if err != nil {
		return nil, err
	}
	if d1.After(d2) {
		return r.AccessKeys[0], nil
	}
	return r.AccessKeys[1], nil
}

func (r *Role) OldestKeyId() (string, error) {
	if len(r.AccessKeys) == 1 {
		return "", nil
	}
	d1, err := time.Parse(time.RFC3339, r.AccessKeys[0].CreateDate)
	if err != nil {
		return "", err
	}
	d2, err := time.Parse(time.RFC3339, r.AccessKeys[1].CreateDate)
	if err != nil {
		return "", err
	}
	if d1.Before(d2) {
		return r.AccessKeys[0].AccessKeyId, nil
	}
	return r.AccessKeys[1].AccessKeyId, nil
}

func (r *Role) SetAccessKey(oldestKeyId string, key *AccessKey) {
	if len(r.AccessKeys) < 2 {
		r.AccessKeys = append(r.AccessKeys, key)
	} else {
		if r.AccessKeys[0].AccessKeyId == oldestKeyId {
			r.AccessKeys[0] = key
		} else {
			r.AccessKeys[1] = key
		}
	}
}
