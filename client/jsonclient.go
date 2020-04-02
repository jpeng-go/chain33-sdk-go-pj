// Copyright Fuzamei Corp. 2020 All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jsonclient 实现JSON rpc客户端请求功能
package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// JSONClient a object of jsonclient
type JSONClient struct {
	url       string
	prefix    string
	tlsVerify bool
	client    *http.Client
	key       []byte
}

func addPrefix(prefix, name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	return prefix + "." + name
}

// NewJSONClient produce a json object
func NewJSONClient(url string, key []byte) (*JSONClient, error) {
	return New("Chain33", url, false, key)
}

// New produce a jsonclient by perfix and url
func New(prefix, url string, tlsVerify bool, key []byte) (*JSONClient, error) {
	httpcli := http.DefaultClient
	if strings.Contains(url, "https") { //暂不校验tls证书
		httpcli = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify}}}
	}
	return &JSONClient{
		url:       url,
		prefix:    prefix,
		tlsVerify: tlsVerify,
		client:    httpcli,
		key:       key,
	}, nil
}

type clientRequest struct {
	Method string         `json:"method"`
	Params [1]interface{} `json:"params"`
	ID     uint64         `json:"id"`
}

type clientResponse struct {
	ID     uint64           `json:"id"`
	Result *json.RawMessage `json:"result"`
	Error  interface{}      `json:"error"`
}

func (client *JSONClient) Call(method string, params, resp interface{}) error {
	method = addPrefix(client.prefix, method)
	req := &clientRequest{}
	req.Method = method
	req.Params[0] = params
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	postresp, err := client.client.Post(client.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer postresp.Body.Close()
	b, err := ioutil.ReadAll(postresp.Body)
	if err != nil {
		return err
	}
	cresp := &clientResponse{}
	err = json.Unmarshal(b, &cresp)
	if err != nil {
		return err
	}
	if cresp.Error != nil {
		x, ok := cresp.Error.(string)
		if !ok {
			return fmt.Errorf("invalid error %v", cresp.Error)
		}
		if x == "" {
			x = "unspecified error"
		}
		return fmt.Errorf(x)
	}
	if cresp.Result == nil {
		return errors.New("Empty result")
	}
	return json.Unmarshal(*cresp.Result, resp)
}

// 发送交易
func (client *JSONClient) SendTransaction(signedTx string) (string, error) {
	var res string
	send := &RawParm{
		Token: "BTY",
		Data: signedTx,
	}
	err := client.Call("Chain33.CreateTransaction", send, &res)
	if err != nil {
		return "", err
	}

	return res, nil
}

// 查询交易
func (client *JSONClient) QueryTransaction(hash string) (*TransactionDetail, error) {
	query := QueryParm{
		Hash: hash,
	}
	var detail TransactionDetail
	err := client.Call("Chain33.QueryTransaction", query, &detail)
	if err != nil {
		return nil, err
	}

	return &detail, nil
}