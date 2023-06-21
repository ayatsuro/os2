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

type VdcUser struct {
	Password        string `json:"password"`
	IsSystemAdmin   string `json:"isSystemAdmin"`
	IsSystemMonitor string `json:"isSystemMonitor"`
	IsSecurityAdmin string `json:"isSecurityAdmin"`
}

type AccessKey struct {
	AccessKeyId     string `json:"AccessKeyId"`
	UserName        string `json:"UserName"`
	SecretAccessKey string `json:"SecretAccessKey,omitempty"`
	CreateDate      string `json:"CreateDate"`
}

type CreateAccessKey struct {
	CreateAccessKeyResult CreateAccessKeyResult `json:"CreateAccessKeyResult"`
}

type CreateAccessKeyResult struct {
	AccessKey AccessKey `json:"AccessKey"`
}

type NativeUsers struct {
	Users []NativeUser `json:"blobuser"`
}

type NativeUser struct {
	Userid string `json:"userid,omitempty"`
	Name   string `json:"name,omitempty"`
}

type ListAccessKeys struct {
	ListAccessKeysResult AccessKeyMetadata `json:"ListAccessKeysResult"`
}

type AccessKeyMetadata struct {
	AccessKeys []AccessKey `json:"AccessKeyMetadata"`
}
