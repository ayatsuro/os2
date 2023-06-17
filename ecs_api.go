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

func (e *ecsClient) onboardNamespace(namespace, username string) *EcsError {
	blog.Info("onboarding namespace " + namespace)
	// 1. check the namespace exists
	var allNs model.Namespaces
	path := "/object/namespaces.json"
	if err := e.API("GET", path, nil, nil, &allNs); err != nil {
		return err
	}
	found := false
	for _, ns := range allNs.Namespace {
		if strings.ToLower(ns.Name) == namespace {
			found = true
			break
		}
	}
	if !found {
		return newError(404, "namespace "+namespace+" not found")
	}
	// 2. check the IAM user does not exist
	var allUsers model.ListIamUsers
	path = "/iam?Action=ListUsers"
	if err := e.API("GET", path, nil, nil, &allUsers); err != nil {
		return err
	}
	debug, _ := json.Marshal(allUsers)
	blog.Info(string(debug))
	found = false
	for _, user := range allUsers.ListUsersResult.Users {
		blog.Info(user.UserName + " " + username)
		if strings.ToLower(user.UserName) == username {
			found = true
			break
		}
	}
	if found {
		return newError(400, "iam user "+username+" already exists")
	}
	blog.Info("namespace "+namespace, username+"onboarded")
	return nil
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

func (e *ecsClient) API(method, path string, headers http.Header, data any, obj any) *EcsError {
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
		return newError(500, "reaching ECS "+err.Error())
	}
	// if token has expired, we login again
	if resp.StatusCode == 401 {
		if err := e.login(); err != nil {
			return newError(500, "login to ECS "+err.Error())
		}
		req.Header.Set("X-SDS-AUTH-TOKEN", e.token)
		resp, err = e.client.Do(req)
		if err != nil {
			return newError(500, "reaching ECS "+err.Error())
		}
	}

	defer resp.Body.Close()
	bodyByte, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 300 {
		return newError(resp.StatusCode, string(bodyByte))
	}

	if len(bodyByte) > 0 && obj != nil {
		if err = json.Unmarshal(bodyByte, &obj); err != nil {
			return newError(500, "unmarshalling ECS response "+err.Error())
		}
	}
	return nil
}
