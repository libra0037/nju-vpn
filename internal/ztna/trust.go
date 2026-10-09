package ztna

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// 授信终端：把一台设备绑到账号上，之后这台设备登录时不再要求二次验证。
// 绑定的主体是设备标识（device_id），服务端在登录时把请求里的设备映射到
// 一条终端记录，记录里的 id 就是查询接口返回的 selfId。

// DeviceStatus 是一次查询的结果。
type DeviceStatus struct {
	SelfID       string
	Trusted      bool
	Count        int
	Max          int
	TrustEnabled bool
	// Devices 是全部授信终端（查询接口返回的列表）。
	Devices []DeviceRecord
}

// DeviceRecord 是一条终端记录里的关键字段。
type DeviceRecord struct {
	ID          string `json:"id"`
	DevDbID     string `json:"devDbId"`
	TrustDbID   string `json:"trusDevDbId"`
	DeviceName  string `json:"deviceName"`
	DeviceType  string `json:"deviceType"`
	OS          string `json:"os"`
	Username    string `json:"username"`
	LastLoginIP string `json:"lastLoginIp"`
	LastLoginAt string `json:"lastLoginTime"`
	Online      bool   `json:"onlineStatus"`
	TrustStatus int    `json:"trustStatus"`
	NetworkZone string `json:"lastNetworkZone"`
}

// managementID 是 idList 的标识：查询接口有时只给出 devDbId。
func (d DeviceRecord) managementID() string {
	if d.ID != "" {
		return d.ID
	}
	return d.DevDbID
}

func (s DeviceStatus) hasTrustedDevices() bool {
	return s.Trusted || s.Count != 0 || len(s.Devices) != 0
}

// TrustedIDs 返回列表里所有终端的 id，用于"解除全部"。
func (s DeviceStatus) TrustedIDs() []string {
	out := make([]string, 0, len(s.Devices))
	for _, d := range s.Devices {
		id := d.managementID()
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func (c *control) queryDevice(ctx context.Context, status string) (DeviceStatus, error) {
	var out DeviceStatus
	params := withSharedParams(url.Values{"status": {status}})
	raw, err := c.do(ctx, http.MethodGet, pathQueryDevice, params, nil, nil)
	if err != nil {
		return out, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return out, err
	}
	var d struct {
		SelfID        string `json:"selfId"`
		DeviceTrusted bool   `json:"deviceTrusted"`
		Count         int    `json:"currentTrustDeviceCount"`
		Max           int    `json:"maxDeviceCount"`
		Config        struct {
			Enable bool `json:"enable"`
		} `json:"trustDeviceConfig"`
		Devices []DeviceRecord `json:"data"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return out, &ProtocolError{What: "授信终端列表解析失败"}
	}
	out.SelfID = d.SelfID
	out.Trusted = d.DeviceTrusted
	out.Count = d.Count
	out.Max = d.Max
	out.TrustEnabled = d.Config.Enable
	out.Devices = d.Devices
	return out, nil
}

// trustDevice 绑定。服务端返回值随服务端版本变化，这里只判断调用是否成功。
func (c *control) trustDevice(ctx context.Context, ids []string) error {
	return c.devicePost(ctx, pathTrustDevice, map[string]any{"idList": ids})
}

// untrustDevice 解绑。服务端只接受 idList——用设备管理页里那个
// trustIdList 字段会被拒（400），所以这里不提供那个形态。
func (c *control) untrustDevice(ctx context.Context, ids []string) error {
	return c.devicePost(ctx, pathUntrustDevice, map[string]any{"idList": ids})
}

func (c *control) devicePost(ctx context.Context, path string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw, err := c.do(ctx, http.MethodPost, path, withSharedParams(nil), body, nil)
	if err != nil {
		return err
	}
	_, err = envelopeData(raw)
	return err
}
