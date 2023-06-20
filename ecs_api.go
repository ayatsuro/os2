package os2

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		return nil, errors.New("namespace " + namespace + " not found")
	}
	// 2. check the IAM user does not exist
	found, err = e.checkIamUserExists(namespace, username)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, errors.New("iam user " + username + " already exists")
	}
	// 3. create the access key
	return e.createIamUserAndKey(namespace, username)

}

func (e *ecsClient) migrateNamespace(namespace string) ([]*model.Role, error) {
	// 1. check the namespace exists
	found, err := e.checkNsExists(namespace)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("namespace " + namespace + " not found")
	}
	// 2. list iam users, and for each of them check there is only 1 access key
	//    if only one access key, create a new access key
	users, err := e.getIamUsers(namespace)
	if err != nil {
		return nil, err
	}
	var roles []*model.Role
	for _, user := range users {
		role, err := e.createAccessKey(namespace, user.UserName)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
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
				break
			}
		}
		if !found {
			role, err := e.onboardIamUser(namespace, user.Name, false)
			if err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}

	}
	return roles, nil
}

func (e *ecsClient) onboardIamUser(namespace, username string, checkNsExists bool) (*model.Role, error) {
	// check the ns exists
	if checkNsExists {
		found, err := e.checkNsExists(namespace)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("namespace not found")
		}
	}
	// check username not already exists
	found, err := e.checkIamUserExists(namespace, username)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, errors.New("iam user already exists")
	}
	// create iam user
	return e.createIamUserAndKey(namespace, username)
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
	users, err := e.getIamUsers(namespace)
	if err != nil {
		return false, err
	}
	for _, user := range users {
		if strings.ToLower(user.UserName) == username {
			return true, nil
		}
	}
	return false, nil
}

func (e *ecsClient) createIamUser(namespace, username string) error {
	path := "/iam?Action=CreateUser&UserName=" + username
	return e.API(POST, path, namespace, nil, nil)
}

func (e *ecsClient) createIamUserAndKey(namespace, username string) (*model.Role, error) {
	if err := e.createIamUser(namespace, username); err != nil {
		return nil, err
	}
	return e.createAccessKey(namespace, username)
}

func (e *ecsClient) createAccessKey(namespace, username string) (*model.Role, error) {
	var key model.CreateAccessKey
	path := "/iam?Action=CreateAccessKey&UserName=" + username
	if err := e.API(POST, path, namespace, nil, &key); err != nil {
		return nil, err
	}
	role := key.CreateAccessKeyResult.AccessKey.ToRoleEntry(namespace)
	return role, nil
}

func (e *ecsClient) checkNsExists(name string) (bool, error) {
	var allNs model.Namespaces
	path := "/object/namespaces.json"
	if err := e.API(GET, path, "", nil, &allNs); err != nil {
		return false, err
	}
	for _, ns := range allNs.Namespace {
		if strings.ToLower(ns.Name) == name {
			return true, nil
		}
	}
	return false, nil
}

func (e *ecsClient) deleteNamespace(name string) error {
	path := "/object/namespaces/namespace/" + name + "/deactivate.json"
	return e.API(POST, path, "", nil, nil)
}

func (e *ecsClient) deleteAccessKey(namespace, username, accessKeyId string) error {
	path := "/iam?Action=DeleteAccessKey&UserName=" + username + "&AccessKeyId=" + accessKeyId
	return e.API(POST, path, namespace, nil, nil)
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
		return errors.New(strconv.Itoa(resp.StatusCode) + " " + string(bodyByte))
	}

	if len(bodyByte) > 0 && obj != nil {
		if err = json.Unmarshal(bodyByte, &obj); err != nil {
			return err
		}
	}
	return nil
}
