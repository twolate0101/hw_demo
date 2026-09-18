package fingerprint

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/twolate0101/hw_demo/internal/model"
)

func testEngine(t *testing.T) Engine {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	e, err := NewEngine(filepath.Join(filepath.Dir(file), "..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestIdentify(t *testing.T) {
	e := testEngine(t)
	mysqlPayload := append([]byte{0x0a}, []byte("8.0.36\x00")...)
	mysqlPayload = append(mysqlPayload, 1, 0, 0, 0)
	mysql := append([]byte{byte(len(mysqlPayload)), 0, 0, 0}, mysqlPayload...)

	tests := []struct {
		name, banner, protocol, product, version, os string
	}{
		{"OpenSSH on nonstandard port", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n", "HTTP", "nginx", "1.24.0", ""},
		{"Apache", "HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.57 (Debian)\r\n", "HTTP", "Apache", "2.4.57", "Debian"},
		{"Jetty", "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.53.v20231009)\r\n", "HTTP", "Jetty", "9.4.53.v20231009", ""},
		{"Jetty slash", "HTTP/1.1 404 Not Found\r\nServer: Jetty/12.0.8\r\n", "HTTP", "Jetty", "12.0.8", ""},
		{"IIS", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "HTTP", "Microsoft-IIS", "10.0", "Windows"},
		{"MySQL", string(mysql), "MySQL", "MySQL", "8.0.36", ""},
		{"MySQL truncated", "J\x00\x00\x00\x0a8.0.32\x00", "MySQL", "MySQL", "8.0.32", ""},
		{"Redis PONG", "+PONG\r\n", "Redis", "Redis", "", ""},
		{"Redis NOAUTH", "-NOAUTH Authentication required.\r\n", "Redis", "Redis", "", ""},
		{"Redis wrong args", "-ERR wrong number of arguments for 'get' command\r\n", "Redis", "Redis", "", ""},
		{"ProFTPD", "220 ProFTPD 1.3.8 Server ready\r\n", "FTP", "ProFTPD", "1.3.8", ""},
		{"vsFTPd", "220 (vsFTPd 3.0.5)\r\n", "FTP", "vsFTPd", "3.0.5", ""},
		{"Pure-FTPd", "220-Welcome to Pure-FTPd 1.0.51\r\n", "FTP", "Pure-FTPd", "1.0.51", ""},
		{"generic HTTP", "HTTP/1.0 404 Not Found\r\nDate: now\r\n", "HTTP", "", "", ""},
		{"generic SSH", "SSH-2.0-dropbear_2022.83\r\n", "SSH", "SSH server", "", ""},
		{"generic FTP", "220 Acme FTP service ready\r\n", "FTP", "", "", ""},
		{"TLS", string([]byte{0x16, 0x03, 0x03, 0, 10}), "TLS", "", "", ""},
		{"unknown", "QUIT\r\n", "unknown", "", "", ""},
		{"empty", "", "unknown", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.Identify(model.ScanInput{IP: "127.0.0.1", Port: 12345, Banner: tt.banner})
			if got.Protocol != tt.protocol || got.Product != tt.product || got.Version != tt.version || got.OSHint != tt.os {
				t.Fatalf("got protocol=%q product=%q version=%q os=%q", got.Protocol, got.Product, got.Version, got.OSHint)
			}
			if got.IP != "127.0.0.1" || got.Port != 12345 {
				t.Fatalf("input identity was not preserved: %+v", got)
			}
		})
	}
}

func TestNewEngineRejectsBadRules(t *testing.T) {
	for _, path := range []string{"does-not-exist.json"} {
		if _, err := NewEngine(path); err == nil {
			t.Fatalf("NewEngine(%q) unexpectedly succeeded", path)
		}
	}
}
