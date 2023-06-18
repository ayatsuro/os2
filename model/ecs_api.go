package model

type Namespaces struct {
	Namespace []Namespace `json:"namespace"`
}

type Namespace struct {
	Name string `json:"name"`
}

type ListIamUsers struct {
	ListUsersResult IamUsers `json:"ListUsersResult"`
}

type IamUsers struct {
	Users []IamUser `json:"Users"`
}

type IamUser struct {
	UserName string `json:"UserName"`
}

type AccessKey struct {
	AccessKeyId     string `json:"AccessKeyId"`
	UserName        string `json:"UserName"`
	SecretAccessKey string `json:"SecretAccessKey,omitempty"`
}

func (k AccessKey) ToRoleEntry(ns string) *Role {
	return &Role{
		Username:        k.UserName,
		AccessKeyId:     k.AccessKeyId,
		SecretAccessKey: k.SecretAccessKey,
		Namespace:       ns,
		TTL:             0,
		MaxTTL:          0,
	}
}

type CreateAccessKey struct {
	CreateAccessKeyResult CreateAccessKeyResult `json:"CreateAccessKeyResult"`
}

type CreateAccessKeyResult struct {
	AccessKey AccessKey `json:"AccessKey"`
}

type ListAccessKeys struct {
	ListAccessKeysResult ListAccessKeysResult `json:"ListAccessKeysResult"`
}

type ListAccessKeysResult struct {
	AccessKeyMetadata []AccessKey `json:"AccessKeyMetadata"`
}

type NativeUsers struct {
	Users []NativeUser `json:"blobuser"`
}

type NativeUser struct {
	Userid string `json:"userid,omitempty"`
	Name   string `json:"name,omitempty"`
}
