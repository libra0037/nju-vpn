module njuvpn

go 1.24

require github.com/refraction-networking/utls v1.8.2

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/kardianos/service v1.3.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// 后续接入时再加（版本已确认，见 NOTES.md）：
//   golang.zx2c4.com/wireguard  v0.0.0-20260522210424-ecfc5a8d5446
//   github.com/kardianos/service v1.3.0
//   github.com/Microsoft/go-winio  v0.6.2        // 仅 Windows 命名管道
//   github.com/pquerna/otp         v1.5.0
//   gopkg.in/yaml.v3               v3.0.1
