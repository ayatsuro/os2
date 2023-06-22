package os2

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	pwdGen "github.com/sethvargo/go-password/password"
	"io"
	"net/http"
	"os2/model"
	"strconv"
	"strings"
)

const (
	nsHeaderName = "x-emc-namespace"
	GET          = "GET"
	POST         = "POST"
	PUT          = "PUT"
)

type ecsClient struct {
	client   *http.Client
	username string
	url      string
	password string
	token    string
}

func newClient(config *model.PluginConfig) (*ecsClient, error) {
	client := new(ecsClient)
	client.url = config.Url
	client.username = config.Username
	client.password = config.Password
	client.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipSsl}}}
	if err := client.login(); err != nil {
		return nil, err
	}
	return client, nil
}

func (e *ecsClient) onboardNamespace(namespace, username string) (*model.Role, error) {
	// 1. check the namespace exists
	found, err := e.checkNsExists(namespace)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("namespace %s not found", namespace)
	}
	// 2. create the iam user and its access key
	key, err := e.createIamUserAndKey(namespace, username)
	if err != nil {
		return nil, err
	}
	role := model.Role{
		Username:   username,
		AccessKey1: key,
		Namespace:  namespace,
		TTL:        0,
		MaxTTL:     0,
	}
	return &role, nil
}

func (e *ecsClient) migrateNamespace(namespace string) ([]*model.Role, error) {
	// 1. check the namespace exists
	found, err := e.checkNsExists(namespace)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("namespace %s not found", namespace)
	}
	// 2. list iam users, and for each of them check there is only 1 access key
	//    if only one access key, create a new access key
	users, err := e.getIamUsers(namespace)
	if err != nil {
		return nil, err
	}
	var roles []*model.Role
	// we check all iam users have at most 1 key before creating anything
	for _, user := range users {
		keys, err := e.listAccessKeys(namespace, user.UserName)
		if err != nil {
			return nil, err
		}
		if len(keys) == 2 {
			return nil, fmt.Errorf("user %v can't be migrated, it has already 2 access keys", user.UserName)
		}
	}
	for _, user := range users {
		key, err := e.createAccessKey(namespace, user.UserName)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &model.Role{
			Username:   user.UserName,
			AccessKey1: key,
			Namespace:  namespace,
			TTL:        0,
			MaxTTL:     0,
		})
	}
	// 3 list native users, and if not found in iam users, create an iam user and its access key
	path := "/object/users/" + namespace + ".json"
	var nativeUsers model.NativeUsers
	if err := e.API(GET, path, "", nil, &nativeUsers); err != nil {
		return nil, err
	}
	nUsers := nativeUsers.Users
	for _, user := range nUsers {
		path := "/object/users/" + user.Userid + "/info.json"
		// we complete the native user with the name
		// since we don't need it outside of the loop, we're fine to only update the local variable user
		if err := e.API(GET, path, "", nil, &user); err != nil {
			return nil, err
		}
		found := false
		for _, role := range roles {
			if role.Username == user.Name {
				found = true
			}
		}
		if !found {
			role, err := e.createIamUser(namespace, user.Name, false)
			if err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}

	}
	return roles, nil
}

func (e *ecsClient) createIamUser(namespace, username string, checkNsExists bool) (*model.Role, error) {
	// check the ns exists
	if checkNsExists {
		found, err := e.checkNsExists(namespace)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("namespace %s not found", namespace)
		}
	}
	// check username not already exists
	found, err := e.checkIamUserExists(namespace, username)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, fmt.Errorf("iam user %s already exists in namespace %s", username, namespace)
	}
	// create iam user
	key, err := e.createIamUserAndKey(namespace, username)
	if err != nil {
		return nil, err
	}
	role := model.Role{
		Username:   username,
		AccessKey1: key,
		Namespace:  namespace,
		TTL:        0,
		MaxTTL:     0,
	}
	return &role, nil

}

func (e *ecsClient) getIamUsers(namespace string) ([]model.IamUser, error) {
	var allUsers model.ListIamUsers
	path := "/iam?Action=ListUsers"
	if err := e.API(GET, path, namespace, nil, &allUsers); err != nil {
		return nil, err
	}
	return allUsers.ListUsersResult.Users, nil
}

func (e *ecsClient) checkIamUserExists(namespace, username string) (bool, error) {
	path := "/iam?Action=GetUser&UserName=" + username
	if err := e.API(GET, path, namespace, nil, nil); err != nil {
		if apiErr, ok := err.(*ApiError); ok {
			if apiErr.Code == 404 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func (e *ecsClient) createIamUserAndKey(namespace, username string) (*model.AccessKey, error) {
	path := "/iam?Action=CreateUser&UserName=" + username
	if err := e.API(POST, path, namespace, nil, nil); err != nil {
		return nil, err
	}
	path = "/iam?Action=AttachUserPolicy&PolicyArn=urn:ecs:iam:::policy/ECSS3FullAccess&UserName=" + username
	if err := e.API(POST, path, namespace, nil, nil); err != nil {
		return nil, err
	}
	return e.createAccessKey(namespace, username)
}

func (e *ecsClient) createAccessKey(namespace, username string) (*model.AccessKey, error) {
	var response model.CreateAccessKey
	path := "/iam?Action=CreateAccessKey&UserName=" + username
	if err := e.API(POST, path, namespace, nil, &response); err != nil {
		return nil, err
	}
	key := response.CreateAccessKeyResult.AccessKey
	return &key, nil
}

func (e *ecsClient) listAccessKeys(namespace, username string) ([]model.AccessKey, error) {
	var response model.ListAccessKeys
	path := "/iam?Action=ListAccessKeys&UserName=" + username
	if err := e.API(POST, path, namespace, nil, &response); err != nil {
		return nil, err
	}
	keys := response.ListAccessKeysResult.AccessKeys
	return keys, nil
}

func (e *ecsClient) checkNsExists(name string) (bool, error) {
	path := fmt.Sprintf("/object/namespaces/namespace/%s.json", name)
	if err := e.API(GET, path, "", nil, nil); err != nil {
		if apiErr, ok := err.(*ApiError); ok {
			if apiErr.Code == 404 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func (e *ecsClient) deleteIamUser(namespace, username string) error {
	path := "/iam?Action=DeleteUser&UserName=" + username
	if err := e.API(POST, path, namespace, nil, nil); err != nil {
		if apiErr, ok := err.(*ApiError); ok {
			if apiErr.Code == 404 {
				return nil
			}
		}
		return err
	}
	return nil
}

func (e *ecsClient) deleteAccessKey(namespace, username, accessKeyId string) error {
	path := "/iam?Action=DeleteAccessKey&UserName=" + username + "&AccessKeyId=" + accessKeyId
	if err := e.API(POST, path, namespace, nil, nil); err != nil {
		if apiErr, ok := err.(*ApiError); ok {
			if apiErr.Code == 404 {
				return nil
			}
		}
		return err
	}
	return nil
}

func (e *ecsClient) rotatePwd(username string) (string, error) {
	gen, err := pwdGen.NewGenerator(&pwdGen.GeneratorInput{
		Symbols: "!@#$%^&"})
	if err != nil {
		return "", err
	}
	pwd, err := gen.Generate(8, 1, 1, false, false)
	if err != nil {
		return "", err
	}
	user := model.VdcUser{
		Password:        pwd,
		IsSystemAdmin:   "true",
		IsSystemMonitor: "false",
		IsSecurityAdmin: "false",
	}
	path := "/vdc/users/" + username + ".json"
	return pwd, e.API(PUT, path, "", user, nil)
}
func (e *ecsClient) login() error {
	req, err := http.NewRequest(GET, e.url+"/login", nil)
	if err != nil {
		return err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(e.username + ":" + e.password))
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("ECS login " + strconv.Itoa(resp.StatusCode))
	}
	var token string
	for k, v := range resp.Header {
		if k == "X-Sds-Auth-Token" {
			token = v[0]
			break
		}
	}
	if token == "" {
		return errors.New("ECS login X-Sds-Auth-Token header not found")
	}
	e.token = token
	return nil
}

func (e *ecsClient) API(method, path, namespace string, data any, obj any) error {
	if !strings.HasPrefix(path, "http") {
		path = e.url + path
	}
	var req *http.Request
	if data != nil {
		payload, _ := json.Marshal(data)
		req, _ = http.NewRequest(method, path, bytes.NewBuffer(payload))
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}

	if namespace != "" {
		req.Header = http.Header{nsHeaderName: {namespace}}
	}
	req.Header.Add("X-SDS-AUTH-TOKEN", e.token)
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	// if token has expired, we log in again
	if resp.StatusCode == 401 {
		if err := e.login(); err != nil {
			return err
		}
		req.Header.Set("X-SDS-AUTH-TOKEN", e.token)
		resp, err = e.client.Do(req)
		if err != nil {
			return err
		}
	}

	defer resp.Body.Close()
	bodyByte, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 300 {
		return newApiError(resp.StatusCode, string(bodyByte))
	}

	if len(bodyByte) > 0 && obj != nil {
		if err = json.Unmarshal(bodyByte, &obj); err != nil {
			return err
		}
	}
	return nil
}

type ApiError struct {
	Code int
	Msg  string
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Msg)
}

func newApiError(code int, msg string) *ApiError {
	return &ApiError{
		Code: code,
		Msg:  msg,
	}
}
