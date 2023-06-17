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

func (e *ecsClient) onboardNamespace(namespace, username string) (*model.RoleEntry, error) {
	blog.Info("onboard " + namespace + " " + username)
	var roleEntry *model.RoleEntry
	// 1. check the namespace exists
	var allNs model.Namespaces
	path := "/object/namespaces.json"
	if err := e.API("GET", path, nil, nil, &allNs); err != nil {
		blog.Error(err.Error())
		return roleEntry, err
	}
	found := false
	for _, ns := range allNs.Namespace {
		if strings.ToLower(ns.Name) == namespace {
			found = true
			break
		}
	}
	if !found {
		return roleEntry, errors.New("namespace " + namespace + " not found")
	}
	// 2. check the IAM user does not exist
	var allUsers model.ListIamUsers
	path = "/iam?Action=ListUsers"
	if err := e.API("GET", path, nil, nil, &allUsers); err != nil {
		return roleEntry, err
	}
	found = false
	for _, user := range allUsers.ListUsersResult.Users {
		if strings.ToLower(user.UserName) == username {
			found = true
			break
		}
	}
	if found {
		return roleEntry, errors.New("iam user " + username + " already exists")
	}
	// 3. create the access key
	var key model.CreateAccessKey
	path = "/iam?Action=CreateAccessKey&UserName=" + username
	if err := e.API("POST", path, nil, nil, &key); err != nil {
		blog.Error(err.Error())
		return roleEntry, err
	}
	roleEntry = key.CreateAccessKeyResult.AccessKey.ToRoleEntry(namespace)
	debug(roleEntry)
	return roleEntry, nil
}

func (e *ecsClient) deleteNamespace(name string) error {
	path := "/object/namespaces/namespace/" + name + "/deactivate.json"
	return e.API("POST", path, nil, nil, nil)
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
