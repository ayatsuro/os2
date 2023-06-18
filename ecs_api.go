package os2

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os2/model"
	"strconv"
	"strings"
)

const nsHeaderName = "x-emc-namespace"

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
	var role *model.Role
	// 1. check the namespace exists
	found, err := e.checkNsExists(namespace)
	if err != nil {
		return role, err
	}
	if !found {
		return role, errors.New("namespace " + namespace + " not found")
	}
	// 2. check the IAM user does not exist
	header := http.Header{nsHeaderName: {namespace}}
	var allUsers model.ListIamUsers
	path := "/iam?Action=ListUsers"
	if err := e.API("GET", path, header, nil, &allUsers); err != nil {
		return role, err
	}
	found = false
	for _, user := range allUsers.ListUsersResult.Users {
		if strings.ToLower(user.UserName) == username {
			found = true
			break
		}
	}
	if found {
		return role, errors.New("iam user " + username + " already exists")
	}
	// 3. create the access key
	var key model.CreateAccessKey
	path = "/iam?Action=CreateAccessKey&UserName=" + username
	if err := e.API("POST", path, header, nil, &key); err != nil {
		return role, err
	}
	role = key.CreateAccessKeyResult.AccessKey.ToRoleEntry(namespace)
	return role, nil
}

func (e *ecsClient) migrateNamespace(namespace string) ([]*model.Role, error) {
	var roles []*model.Role
	// 1. check the namespace exists
	found, err := e.checkNsExists(namespace)
	if err != nil {
		return roles, err
	}
	if !found {
		return roles, errors.New("namespace " + namespace + " not found")
	}
	// 2. list iam users, and for each of them check there is only access key
	//    if only one access key, create a new access key
	header := http.Header{nsHeaderName: {namespace}}
	var allUsers model.ListIamUsers
	path := "/iam?Action=ListUsers"
	if err := e.API("GET", path, header, nil, &allUsers); err != nil {
		return roles, err
	}
	for _, user := range allUsers.ListUsersResult.Users {

	}
	// 3 list native users, and if not found in iam users, create an iam user and its access key

	return nil, nil
}

func (e *ecsClient) checkNsExists(name string) (bool, error) {
	var allNs model.Namespaces
	path := "/object/namespaces.json"
	if err := e.API("GET", path, nil, nil, &allNs); err != nil {
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
	return e.API("POST", path, nil, nil, nil)
}

func (e *ecsClient) deleteAccessKey(namespace, username, accessKeyId string) error {
	header := http.Header{nsHeaderName: {namespace}}
	path := "/iam?Action=DeleteAccessKey&UserName=" + username + "&AccessKeyId=" + accessKeyId
	return e.API("POST", path, header, nil, nil)
}

func (e *ecsClient) login() error {
	req, err := http.NewRequest("GET", e.url+"/login", nil)
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

func (e *ecsClient) API(method, path string, headers http.Header, data any, obj any) error {
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

	if headers != nil {
		req.Header = headers
	}
	req.Header.Add("X-SDS-AUTH-TOKEN", e.token)
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	// if token has expired, we login again
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
