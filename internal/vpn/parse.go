package vpn

import (
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
)

// 协议里固定的长度。
const (
	// tokenHexLen 是从 ServerHello SessionId 里取的十六进制字符数。
	tokenHexLen = 31
	// tokenTotalLen 是 token 字节数：31 个十六进制字符加一个结尾的 0。
	tokenTotalLen = tokenHexLen + 1
	// twfIDLen 是 TwfID 参与流协议时的长度。
	twfIDLen = 16
	// streamTokenLen 是流协议首包的 token 部分：32 字节 token + 16 字节 TwfID。
	streamTokenLen = tokenTotalLen + twfIDLen
	// streamFrameLen 是流握手报文的总长：4 字节操作码 + token + 8 字节保留 + 4 字节地址。
	streamFrameLen = 4 + streamTokenLen + 8 + 4
	// queryFrameLen 是 query-ip 报文的总长，与流握手报文相同。
	queryFrameLen = streamFrameLen

	// maxBodyBytes 限制从服务端读取的响应体大小。
	maxBodyBytes = 1 << 20
)

// tagRegexps 是协议里用到的全部标签正则，启动时编译一次。
//
// 标签是固定的小集合，查表比 sync.Map 省一次接口断言——这条路径在
// 每次解析响应时都会走到。表里没有的标签仍能用（见 tagRegexp），
// 只是每次都要现场编译正则并记一条日志，所以用到的标签都要登记进来。
var tagRegexps = map[string]*regexp.Regexp{
	"TwfID":              tagPattern("TwfID"),
	"Result":             tagPattern("Result"),
	"NextAuth":           tagPattern("NextAuth"),
	"NextService":        tagPattern("NextService"),
	"NextServiceSubType": tagPattern("NextServiceSubType"),
	"ErrorCode":          tagPattern("ErrorCode"),
	"ErrorMsg":           tagPattern("ErrorMsg"),
	"Note":               tagPattern("Note"),
	"Message":            tagPattern("Message"),
	"CSRF_RAND_CODE":     tagPattern("CSRF_RAND_CODE"),
	"RSA_ENCRYPT_KEY":    tagPattern("RSA_ENCRYPT_KEY"),
	"RSA_ENCRYPT_EXP":    tagPattern("RSA_ENCRYPT_EXP"),
	"IS_IN_PERIOD":       tagPattern("IS_IN_PERIOD"),
	"SmsSendInterval":    tagPattern("SmsSendInterval"),
	"USER_PHONE":         tagPattern("USER_PHONE"),
	"T_SMSINFOR":         tagPattern("T_SMSINFOR"),
	"SMS_INTERVAL":       tagPattern("SMS_INTERVAL"),
	"g_DisableTime":      tagPattern("g_DisableTime"),
}

// tagPattern 编译一个标签的取值正则。
//
// (?s) 让点号也匹配换行（服务端会在 CDATA 里放多行文本），
// 非贪婪避免同一行出现两个同名标签时从第一个开标签吃到最后一个闭标签。
func tagPattern(tag string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(tag)
	return regexp.MustCompile("(?s)<" + quoted + ">(.*?)</" + quoted + ">")
}

func tagRegexp(tag string) *regexp.Regexp {
	if re, ok := tagRegexps[tag]; ok {
		return re
	}
	// 不在表里的标签：协议里不该出现，但解析器不能因此崩掉。
	// 编译结果不进表（表是只读的），顺手记一条日志方便发现。
	re := tagPattern(tag)
	log.Printf("vpn: 未登记的标签 %q，已临时编译正则", tag)
	return re
}

// tagValue 取出 <tag>...</tag> 的内容，标签不存在时 ok 为 false。
func tagValue(body []byte, tag string) (string, bool) {
	m := tagRegexp(tag).FindSubmatch(body)
	if m == nil {
		return "", false
	}
	return stripCDATA(string(m[1])), true
}

// stripCDATA 去掉值外层的 CDATA 包装。服务端两种写法混用。
func stripCDATA(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<![CDATA[") && strings.HasSuffix(s, "]]>") {
		return strings.TrimSpace(s[len("<![CDATA[") : len(s)-len("]]>")])
	}
	return s
}

// requireTag 取标签，缺失时返回可诊断的协议错误。
func requireTag(step string, body []byte, tag string) (string, error) {
	v, ok := tagValue(body, tag)
	if !ok {
		return "", &ProtocolError{Step: step, Reason: "缺少 <" + tag + "> 标签"}
	}
	return v, nil
}

// hasTag 判断标签是否存在。
func hasTag(body []byte, tag string) bool {
	_, ok := tagValue(body, tag)
	return ok
}

// sessionIDToken 把 TLS ServerHello 的 SessionId 转成协议要求的 token。
//
// 长度校验是必须的：旧实现在这里直接 hex 编码后取前 31 个字符，
// 服务端返回空 SessionId 时就是一次下标越界 panic。
func sessionIDToken(step string, sessionID []byte) (string, error) {
	const need = (tokenHexLen + 1) / 2
	if len(sessionID) < need {
		return "", &ProtocolError{
			Step:   step,
			Reason: fmt.Sprintf("ServerHello SessionId 只有 %d 字节，至少需要 %d 字节", len(sessionID), need),
		}
	}
	return hex.EncodeToString(sessionID)[:tokenHexLen] + "\x00", nil
}

// streamToken 组装流协议首包里的 48 字节：32 字节 token 加 16 字节 TwfID。
//
// 旧实现是 (*[48]byte)([]byte(token+twfID))，长度不对时要么 panic、
// 要么静默截断，两种都很难查。这里显式校验。
func streamToken(step, token, twfID string) ([streamTokenLen]byte, error) {
	var out [streamTokenLen]byte
	if len(token) != tokenTotalLen {
		return out, &ProtocolError{
			Step:   step,
			Reason: fmt.Sprintf("token 长度 %d，期望 %d", len(token), tokenTotalLen),
		}
	}
	if len(twfID) < twfIDLen {
		return out, &ProtocolError{
			Step:   step,
			Reason: fmt.Sprintf("TwfID 长度 %d，至少需要 %d", len(twfID), twfIDLen),
		}
	}
	copy(out[:], token)
	// 服务端历史上一直是 16 字节，长于 16 时取前 16 字节（与旧行为一致），
	// 短于 16 时上面的校验会拦住。
	copy(out[tokenTotalLen:], twfID[:twfIDLen])
	return out, nil
}
