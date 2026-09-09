module njuvpn

go 1.24

require github.com/refraction-networking/utls v1.8.2

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

// 后续接入时再加（版本已确认，见 NOTES.md）：
//   golang.zx2c4.com/wireguard  v0.0.0-20260522210424-ecfc5a8d5446
//   github.com/kardianos/service v1.3.0
//   github.com/Microsoft/go-winio  v0.6.2        // 仅 Windows 命名管道
//   github.com/pquerna/otp         v1.5.0
//   gopkg.in/yaml.v3               v3.0.1
