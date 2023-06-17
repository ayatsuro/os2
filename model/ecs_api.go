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
