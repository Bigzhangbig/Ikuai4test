//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var version = "dev"

const (
	ifNameSize = 16
	iffTun     = 0x0001
	iffNoPI    = 0x1000
	tunSetIFF  = 0x400454ca
)

type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	Pad   [22]byte
}

type Check struct {
	Name    string      `json:"name"`
	OK      bool        `json:"ok"`
	Detail  string      `json:"detail,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Elapsed string      `json:"elapsed,omitempty"`
}

type Report struct {
	Version      string            `json:"version"`
	GeneratedAt  string            `json:"generated_at"`
	Mode         string            `json:"mode"`
	Hostname     string            `json:"hostname"`
	GOOS         string            `json:"goos"`
	GOARCH       string            `json:"goarch"`
	UID          int               `json:"uid"`
	EUID         int               `json:"euid"`
	GID          int               `json:"gid"`
	EGID         int               `json:"egid"`
	Namespaces   map[string]string `json:"namespaces"`
	Capabilities map[string]string `json:"capabilities"`
	Checks       []Check           `json:"checks"`
}

type ifaceInfo struct {
	Name  string   `json:"name"`
	MTU   int      `json:"mtu"`
	Flags string   `json:"flags"`
	Addrs []string `json:"addresses"`
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func timed(name string, fn func() Check) Check {
	start := time.Now()
	c := fn()
	c.Name = name
	c.Elapsed = time.Since(start).Round(time.Millisecond).String()
	return c
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func command(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return s, fmt.Errorf("timeout")
	}
	if err != nil {
		return s, err
	}
	return s, nil
}

func interfacesCheck() Check {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	out := make([]ifaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		row := ifaceInfo{Name: iface.Name, MTU: iface.MTU, Flags: iface.Flags.String()}
		for _, a := range addrs {
			row.Addrs = append(row.Addrs, a.String())
		}
		out = append(out, row)
	}
	return Check{OK: true, Data: out}
}

func commandCheck(bin string, args ...string) Check {
	out, err := command(bin, args...)
	if len(out) > 12000 {
		out = out[:12000] + "\n...[truncated]"
	}
	if err != nil {
		return Check{OK: false, Detail: err.Error(), Data: out}
	}
	return Check{OK: true, Data: out}
}

func defaultGateway() (net.IP, string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, "", err
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" {
			continue
		}
		n, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		ip := net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
		return ip, f[0], nil
	}
	return nil, "", errors.New("default gateway not found")
}

func gatewayCheck() Check {
	ip, iface, err := defaultGateway()
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	data := map[string]interface{}{"gateway": ip.String(), "interface": iface}
	ports := []int{80, 443, 53, 5351}
	results := map[string]string{}
	for _, p := range ports {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(p))
		c, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
		if err != nil {
			results[addr] = err.Error()
			continue
		}
		_ = c.Close()
		results[addr] = "connected"
	}
	data["tcp_ports"] = results
	return Check{OK: true, Data: data}
}

func tunCheck() Check {
	st, err := os.Stat("/dev/net/tun")
	if err != nil {
		return Check{OK: false, Detail: "/dev/net/tun: " + err.Error()}
	}
	data := map[string]interface{}{"mode": st.Mode().String()}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return Check{OK: false, Detail: "open: " + err.Error(), Data: data}
	}
	defer f.Close()
	data["open"] = true

	var req ifreq
	copy(req.Name[:], []byte("ikprobe%d"))
	req.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return Check{OK: false, Detail: "TUNSETIFF: " + errno.Error(), Data: data}
	}
	raw := req.Name[:]
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	data["created_interface"] = string(raw)
	data["note"] = "temporary TUN disappears when the file descriptor closes"
	return Check{OK: true, Data: data}
}

func rawSocketCheck() Check {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	_ = syscall.Close(fd)
	return Check{OK: true, Detail: "raw ICMP socket created successfully"}
}

func netAdminCheck() Check {
	name := "ikpdummy0"
	_, _ = command("ip", "link", "del", name)
	out, err := command("ip", "link", "add", name, "type", "dummy")
	if err != nil {
		return Check{OK: false, Detail: err.Error(), Data: out}
	}
	defer command("ip", "link", "del", name)
	if out2, err := command("ip", "link", "set", name, "up"); err != nil {
		return Check{OK: false, Detail: err.Error(), Data: out2}
	}
	return Check{OK: true, Detail: "created and removed a temporary dummy interface"}
}

func sysctlWriteSameCheck(path string) Check {
	v := readFile(path)
	if v == "" {
		return Check{OK: false, Detail: "unable to read " + path}
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return Check{OK: false, Detail: "read=" + v + "; open for write: " + err.Error()}
	}
	defer f.Close()
	if _, err := io.WriteString(f, v+"\n"); err != nil {
		return Check{OK: false, Detail: "read=" + v + "; write same value: " + err.Error()}
	}
	return Check{OK: true, Detail: "value=" + v + "; same-value write succeeded"}
}

func dnsCheck() Check {
	name := getenv("PROBE_DNS_NAME", "www.qq.com")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		return Check{OK: false, Detail: err.Error(), Data: map[string]string{"name": name}}
	}
	return Check{OK: true, Data: map[string]interface{}{"name": name, "addresses": addrs}}
}

func tcpTargetsCheck() Check {
	targets := splitCSV(getenv("PROBE_TCP_TARGETS", "223.5.5.5:53,1.1.1.1:443"))
	results := make(map[string]string, len(targets))
	okAny := false
	for _, addr := range targets {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			results[addr] = err.Error()
			continue
		}
		results[addr] = "connected"
		okAny = true
		_ = c.Close()
	}
	return Check{OK: okAny, Data: results, Detail: "OK means at least one configured external TCP target connected"}
}

func configuredTargetsCheck() Check {
	targets := splitCSV(os.Getenv("PROBE_TARGETS"))
	if len(targets) == 0 {
		return Check{OK: true, Detail: "no PROBE_TARGETS configured"}
	}
	results := make(map[string]string, len(targets))
	okAll := true
	for _, addr := range targets {
		c, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
		if err != nil {
			results[addr] = err.Error()
			okAll = false
			continue
		}
		results[addr] = "connected"
		_ = c.Close()
	}
	return Check{OK: okAll, Data: results}
}

func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func ssdpCheck() Check {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return Check{OK: false, Detail: "listen: " + err.Error()}
	}
	defer conn.Close()
	req := "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	dst := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		return Check{OK: false, Detail: "send: " + err.Error()}
	}
	_ = conn.SetReadDeadline(time.Now().Add(2200 * time.Millisecond))
	var responses []map[string]string
	buf := make([]byte, 8192)
	for len(responses) < 12 {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return Check{OK: false, Detail: err.Error(), Data: responses}
		}
		body := string(buf[:n])
		entry := map[string]string{"source": addr.String()}
		for _, line := range strings.Split(body, "\r\n") {
			p := strings.SplitN(line, ":", 2)
			if len(p) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(p[0]))
			v := strings.TrimSpace(p[1])
			if k == "location" || k == "server" || k == "st" || k == "usn" {
				entry[k] = v
			}
		}
		responses = append(responses, entry)
	}
	if len(responses) == 0 {
		return Check{OK: false, Detail: "no IGD response within 2.2s; this does not prove UPnP is disabled"}
	}
	return Check{OK: true, Data: responses}
}

func natPMPCheck() Check {
	gw, _, err := defaultGateway()
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	addr := &net.UDPAddr{IP: gw, Port: 5351}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write([]byte{0, 0}); err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return Check{OK: false, Detail: err.Error(), Data: map[string]string{"gateway": gw.String()}}
	}
	data := map[string]interface{}{"gateway": gw.String(), "response_hex": hex.EncodeToString(buf[:n])}
	if n >= 12 && buf[0] == 0 && buf[1] == 128 {
		data["result_code"] = binary.BigEndian.Uint16(buf[2:4])
		data["public_ipv4"] = net.IP(buf[8:12]).String()
	}
	return Check{OK: true, Data: data}
}

func pcpCheck() Check {
	gw, _, err := defaultGateway()
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	addr := &net.UDPAddr{IP: gw, Port: 5351}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	defer conn.Close()
	localIP := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	req := make([]byte, 24)
	req[0] = 2
	req[1] = 0
	if localIP != nil {
		req[18] = 0xff
		req[19] = 0xff
		copy(req[20:24], localIP)
	}
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		return Check{OK: false, Detail: err.Error()}
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return Check{OK: false, Detail: err.Error(), Data: map[string]string{"gateway": gw.String()}}
	}
	data := map[string]interface{}{"gateway": gw.String(), "response_hex": hex.EncodeToString(buf[:n])}
	if n >= 24 && buf[0] == 2 {
		data["response_opcode"] = buf[1]
		data["result_code"] = buf[3]
		data["epoch_time"] = binary.BigEndian.Uint32(buf[8:12])
	}
	return Check{OK: true, Data: data}
}

func caps() map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(readFile("/proc/self/status"), "\n") {
		if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") || strings.HasPrefix(line, "CapBnd:") {
			p := strings.Fields(line)
			if len(p) == 2 {
				out[strings.TrimSuffix(p[0], ":")] = p[1]
			}
		}
	}
	return out
}

func namespaces() map[string]string {
	out := map[string]string{}
	for _, n := range []string{"net", "mnt", "pid", "user", "uts"} {
		v, err := os.Readlink("/proc/self/ns/" + n)
		if err == nil {
			out[n] = v
		}
	}
	return out
}

func buildReport() Report {
	host, _ := os.Hostname()
	r := Report{
		Version:      version,
		GeneratedAt:  time.Now().Format(time.RFC3339),
		Mode:         getenv("PROBE_MODE", "unknown"),
		Hostname:     host,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		UID:          os.Getuid(),
		EUID:         os.Geteuid(),
		GID:          os.Getgid(),
		EGID:         os.Getegid(),
		Namespaces:   namespaces(),
		Capabilities: caps(),
	}
	r.Checks = []Check{
		timed("interfaces", interfacesCheck),
		timed("ip_addr", func() Check { return commandCheck("ip", "-details", "addr", "show") }),
		timed("ip_route", func() Check { return commandCheck("ip", "-details", "route", "show", "table", "all") }),
		timed("ip_rule", func() Check { return commandCheck("ip", "rule", "show") }),
		timed("default_gateway", gatewayCheck),
		timed("dns", dnsCheck),
		timed("external_tcp", tcpTargetsCheck),
		timed("configured_tcp_targets", configuredTargetsCheck),
		timed("tun_create", tunCheck),
		timed("raw_socket_CAP_NET_RAW", rawSocketCheck),
		timed("dummy_interface_CAP_NET_ADMIN", netAdminCheck),
		timed("ipv4_forward_write_same", func() Check { return sysctlWriteSameCheck("/proc/sys/net/ipv4/ip_forward") }),
		timed("iptables_filter_read", func() Check { return commandCheck("iptables", "-S") }),
		timed("iptables_nat_read", func() Check { return commandCheck("iptables", "-t", "nat", "-S") }),
		timed("nft_ruleset_read", func() Check { return commandCheck("nft", "list", "ruleset") }),
		timed("listening_sockets", func() Check { return commandCheck("ss", "-lntup") }),
		timed("upnp_ssdp_igd", ssdpCheck),
		timed("nat_pmp_public_address", natPMPCheck),
		timed("pcp_announce", pcpCheck),
		timed("resolv_conf", func() Check {
			v := readFile("/etc/resolv.conf")
			return Check{OK: v != "", Data: v}
		}),
		timed("cgroup", func() Check {
			v := readFile("/proc/1/cgroup")
			return Check{OK: v != "", Data: v}
		}),
	}
	return r
}

var page = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>iKuai Capability Probe</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:1200px;margin:24px auto;padding:0 16px;color:#1f2328}
button{padding:10px 16px;font-size:16px}
pre{background:#0d1117;color:#e6edf3;padding:16px;border-radius:8px;overflow:auto;white-space:pre-wrap}
.small{color:#59636e}
</style>
</head>
<body>
<h1>iKuai Capability Probe</h1>
<p class="small">版本 {{.Version}} · 模式 {{.Mode}}</p>
<p>这是独立于 Tailscale 的 iKuai 4.0 Docker 能力探针。点击运行会测试接口、路由、TUN、NET_ADMIN、NET_RAW、sysctl、iptables/nft、DNS、外网 TCP、指定 LAN 目标以及 UPnP/PCP/NAT-PMP。</p>
<button onclick="run()">运行全部测试</button>
<span id="state"></span>
<pre id="out">点击“运行全部测试”开始。</pre>
<script>
async function run(){
  const state=document.getElementById('state'), out=document.getElementById('out');
  state.textContent=' 运行中…（UPnP/PCP 等测试约需数秒）';
  try{
    const r=await fetch('/api/report',{cache:'no-store'});
    const j=await r.json();
    out.textContent=JSON.stringify(j,null,2);
    state.textContent=' 完成';
  }catch(e){
    state.textContent=' 失败';
    out.textContent=String(e);
  }
}
</script>
</body></html>`))

func pushReportLoop(target string) {
	if strings.TrimSpace(target) == "" {
		return
	}
	go func() {
		// Build the report once, then keep retrying delivery so the receiver
		// can be started before or after the iKuai app.
		time.Sleep(3 * time.Second)
		report := buildReport()
		payload, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "report marshal failed: %v\n", err)
			return
		}
		payload = append(payload, '\n')

		for attempt := 1; ; attempt++ {
			conn, err := net.DialTimeout("tcp", target, 3*time.Second)
			if err != nil {
				fmt.Fprintf(os.Stderr, "report push attempt %d to %s failed: %v\n", attempt, target, err)
				time.Sleep(8 * time.Second)
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write(payload)
			_ = conn.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "report push attempt %d to %s write failed: %v\n", attempt, target, err)
				time.Sleep(8 * time.Second)
				continue
			}
			fmt.Printf("report pushed successfully to %s after %d attempt(s)\n", target, attempt)
			return
		}
	}()
}

func main() {
	port := getenv("PROBE_PORT", "8080")
	mode := getenv("PROBE_MODE", "unknown")
	reportTarget := strings.TrimSpace(os.Getenv("PROBE_REPORT_TCP"))
	pushReportLoop(reportTarget)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "ok version=%s mode=%s\n", version, mode)
	})
	http.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(buildReport())
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, map[string]string{"Version": version, "Mode": mode})
	})

	addr := "0.0.0.0:" + port
	fmt.Printf("ikuai-cap-probe %s mode=%s listening on %s report_target=%q\n", version, mode, addr, reportTarget)
	s := &http.Server{Addr: addr, ReadHeaderTimeout: 5 * time.Second}
	if err := s.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
