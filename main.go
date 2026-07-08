package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
)

// requiredTool maps a CLI binary name to its Go install path
type requiredTool struct {
	binName    string
	installPkg string
}

var tools = []requiredTool{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
}

func main() {
	domain := flag.String("d", "", "target domain (required)")
	save := flag.Bool("s", false, "save results to disk under results/<domain>/")
	output := flag.String("o", "", "custom output file path for live hosts (overrides -s default location)")
	rateLimit := flag.Int("rl", 150, "max requests per second for httpx (rate limit)")
	timeout := flag.Int("timeout", 10, "per-request timeout in seconds for httpx")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: subrecon -d target.com [-s] [-o output.txt] [-rl 150] [-timeout 10]")
		fmt.Println("  -s          save results to disk (results/<domain>/)")
		fmt.Println("  -o          custom output file path for live hosts")
		fmt.Println("  -rl         max requests per second for httpx (default 150)")
		fmt.Println("  -timeout    per-request timeout in seconds (default 10)")
		os.Exit(1)
	}

	ensureToolsInstalled()

	fmt.Printf("[*] Starting recon on: %s\n", *domain)

	subfinderResults := runSubfinder(*domain, *timeout)
	assetfinderResults := runAssetfinder(*domain)

	allSubdomains := mergeAndDedupe(subfinderResults, assetfinderResults)
	fmt.Printf("[*] Found %d unique subdomains\n", len(allSubdomains))

	liveHosts := runHttpx(allSubdomains, *rateLimit, *timeout)
	fmt.Printf("[*] Found %d live hosts\n\n", len(liveHosts))

	fmt.Println("=== LIVE HOSTS ===")
	for _, host := range liveHosts {
		fmt.Println(host)
	}
	fmt.Println("==================")

	switch {
	case *output != "":
		writeLines(*output, liveHosts)
		fmt.Printf("\n[*] Live hosts saved to %s\n", *output)
	case *save:
		saveResults(*domain, allSubdomains, liveHosts)
	default:
		fmt.Println("\n[*] Results printed above only, nothing saved. Use -s or -o to save to disk.")
	}
}

// ensureToolsInstalled checks each required tool is on PATH, and installs it via `go install` if missing
func ensureToolsInstalled() {
	for _, t := range tools {
		_, err := exec.LookPath(t.binName)
		if err == nil {
			continue // already installed
		}

		fmt.Printf("[*] %s not found, installing via go install...\n", t.binName)
		cmd := exec.Command("go", "install", "-v", t.installPkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("[!] Failed to install %s: %v\n", t.binName, err)
			fmt.Println("    Please install it manually and ensure it's in your PATH.")
			os.Exit(1)
		}
	}
}

// runSubfinder runs subfinder against the domain and returns its output lines
func runSubfinder(domain string, timeout int) []string {
	fmt.Println("[*] Running subfinder...")
	cmd := exec.Command("subfinder", "-d", domain, "-silent", "-timeout", strconv.Itoa(timeout))
	return runAndCollectLines(cmd)
}

// runAssetfinder runs assetfinder against the domain and returns its output lines
func runAssetfinder(domain string) []string {
	fmt.Println("[*] Running assetfinder...")
	cmd := exec.Command("assetfinder", "--subs-only", domain)
	return runAndCollectLines(cmd)
}

// runHttpx probes a list of subdomains for live hosts, returns formatted result lines
// rateLimit caps max requests/sec, timeout caps per-request wait time - both forwarded to httpx directly
func runHttpx(subdomains []string, rateLimit int, timeout int) []string {
	fmt.Printf("[*] Probing for live hosts with httpx (rate-limit: %d/s, timeout: %ds)...\n", rateLimit, timeout)

	cmd := exec.Command("httpx",
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-rate-limit", strconv.Itoa(rateLimit),
		"-timeout", strconv.Itoa(timeout),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Printf("[!] Failed to create httpx stdin pipe: %v\n", err)
		os.Exit(1)
	}

	go func() {
		defer stdin.Close()
		for _, sub := range subdomains {
			fmt.Fprintln(stdin, sub)
		}
	}()

	return runAndCollectLines(cmd)
}

// runAndCollectLines runs a command and returns its stdout, line by line
func runAndCollectLines(cmd *exec.Cmd) []string {
	out, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[!] Failed to run command: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Failed to start command: %v\n", err)
		os.Exit(1)
	}

	var lines []string
	scanner := bufio.NewScanner(out)
	// Increase buffer size for tools that output long lines (e.g. httpx with tech-detect)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	cmd.Wait()
	return lines
}

// mergeAndDedupe combines two slices, removes duplicates, and returns a sorted result
func mergeAndDedupe(a, b []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range append(a, b...) {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	sort.Strings(result)
	return result
}

// saveResults writes subdomains and live hosts to disk under results/<domain>/
func saveResults(domain string, subdomains, liveHosts []string) {
	outDir := fmt.Sprintf("results/%s", domain)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("[!] Failed to create output directory: %v\n", err)
		return
	}

	writeLines(fmt.Sprintf("%s/all_subdomains.txt", outDir), subdomains)
	writeLines(fmt.Sprintf("%s/live_hosts.txt", outDir), liveHosts)

	fmt.Printf("\n[*] Results saved in %s/\n", outDir)
	fmt.Println("    - all_subdomains.txt : every unique subdomain found")
	fmt.Println("    - live_hosts.txt      : live hosts with status, title, tech stack")
}

func writeLines(path string, lines []string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("[!] Failed to write %s: %v\n", path, err)
		return
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
}