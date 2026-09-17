package ztna

import (
	"context"
)

// 授信终端：把当前设备绑到账号上，之后这台设备登录不再要求二次验证。
// 绑定的主体是客户端生成并持久化的设备标识；服务端在登录时把它映射成
// 一条终端记录，记录里的 id 就是查询接口给出的 selfId。

// DeviceSession 暴露授信终端的查 / 绑 / 解绑。
//
// 它可以复用一个已经登录的会话（own=false，Close 什么都不做），
// 也可以自带一次登录（own=true，Close 时登出）。
type DeviceSession struct {
	sess *Session
	own  bool
	logf func(format string, args ...any)
}

// Devices 复用当前会话来操作授信终端。
func (s *Session) Devices() *DeviceSession {
	return &DeviceSession{sess: s, logf: s.client.logf}
}

// OpenDevices 为授信终端操作单独登录一次。
//
// 需要验证码时返回 (session, ErrAuthRequired)：调用方拿到验证码后调用
// DeviceSession.Auth 继续，再调用具体的设备操作。
func (c *Client) OpenDevices(ctx context.Context, password string) (*DeviceSession, error) {
	s, err := c.connectLoginOnly(ctx, password)
	d := &DeviceSession{sess: s, own: true, logf: c.logf}
	return d, err
}

// Status 查询授信终端列表与本机状态。
func (d *DeviceSession) Status(ctx context.Context) (DeviceStatus, error) {
	if err := d.requireSession(); err != nil {
		return DeviceStatus{}, err
	}
	return d.sess.ctrl.queryDevice(ctx, "trust")
}

// requireSession 挡住"登录在早期就失败、会话是空的"这种情况。
//
// OpenDevices 即使失败也要返回一个能安全继续用的对象：登录走到一半失败时
// 那个会话占着服务端名额，调用方得拿它去登出。于是空会话也可能被交出去，
// 剩下的方法不能直接解引用。
func (d *DeviceSession) requireSession() error {
	if d == nil || d.sess == nil {
		return &ProtocolError{What: "授信终端操作没有可用会话（登录未能开始）"}
	}
	return nil
}

// Trust 把本机绑成授信终端，返回绑定后的状态。
func (d *DeviceSession) Trust(ctx context.Context) (DeviceStatus, error) {
	st, err := d.Status(ctx)
	if err != nil {
		return st, err
	}
	if st.Trusted {
		return st, nil
	}
	if st.SelfID == "" {
		return st, &ProtocolError{What: "服务端没有给出本机终端标识"}
	}
	if err := d.sess.ctrl.trustDevice(ctx, []string{st.SelfID}); err != nil {
		return st, err
	}
	return d.Status(ctx)
}

// Untrust 解除本机授信；all 为真时解除该账号下全部授信终端。
func (d *DeviceSession) Untrust(ctx context.Context, all bool) (DeviceStatus, error) {
	st, err := d.Status(ctx)
	if err != nil {
		return st, err
	}
	var ids []string
	if all {
		ids = st.TrustedIDs()
	} else {
		for _, rec := range st.Devices {
			if rec.ID == st.SelfID || rec.DevDbID == st.SelfID {
				ids = append(ids, rec.ID)
				break
			}
		}
		if len(ids) == 0 && st.SelfID != "" {
			ids = append(ids, st.SelfID)
		}
	}
	if len(ids) == 0 {
		return st, nil // 本来就没有授信终端
	}
	if err := d.sess.ctrl.untrustDevice(ctx, ids); err != nil {
		return st, err
	}
	return d.Status(ctx)
}

// Auth 在登录需要验证码时继续。
func (d *DeviceSession) Auth(ctx context.Context, code string) error {
	if err := d.requireSession(); err != nil {
		return err
	}
	return d.sess.Auth(ctx, code)
}

// OwnsSession 报告这次授信终端操作是否自带一次登录（而不是复用隧道会话）。
func (d *DeviceSession) OwnsSession() bool { return d != nil && d.own }

// SMSPrompt 让服务端把验证码发出去，并返回给用户看的提示。
//
// 只调用 Hint 是不够的：验证码要到这里才真的发出来。
func (d *DeviceSession) SMSPrompt(ctx context.Context) (string, error) {
	if d.sess == nil {
		return "", nil
	}
	return d.sess.SMSPrompt(ctx)
}

// Hint 返回给用户看的提示（手机号脱敏）。
func (d *DeviceSession) Hint(ctx context.Context) string {
	if d.sess == nil {
		return ""
	}
	return d.sess.smsHint(ctx)
}

// Close 释放这次设备操作占用的登录。
func (d *DeviceSession) Close(ctx context.Context) error {
	if !d.own || d.sess == nil {
		return nil
	}
	return d.sess.Close(ctx)
}

// EnsureTrusted 保证本机是授信终端：已经授信就什么都不做。
//
// 它复用当前会话，不额外登录——服务端同一账号只允许一条会话。
// 用于 `njuvpn start --trust`，以及它中途要做二次验证时的续跑。
func (s *Session) EnsureTrusted(ctx context.Context) error {
	d := s.Devices()
	st, err := d.Status(ctx)
	if err != nil {
		return err
	}
	if st.Trusted {
		s.client.logf("本机已是授信终端（%d/%d）", st.Count, st.Max)
		return nil
	}
	st, err = d.Trust(ctx)
	if err != nil {
		return err
	}
	s.client.logf("已绑定为授信终端（%d/%d），之后登录免二次验证", st.Count, st.Max)
	return nil
}
