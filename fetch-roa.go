package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BaseURL    = "https://stats.labs.apnic.net/roa"
	OutputDir  = "data/parsed"
	UserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
)

var (
	asnRegex   = regexp.MustCompile(`>AS(\d+)<`)
	scoreRegex = regexp.MustCompile(`\{v:\s*([\d\.]+)`)
)

func main() {
	countriesFlag := flag.String("countries", "", "Comma separated list of country codes for bulk sync")
	asnsFlag := flag.String("asns", "", "Comma separated list of ASNs for targeted sync")
	workersFlag := flag.Int("workers", 10, "Number of concurrent workers")
	flag.Parse()

	if *countriesFlag == "" && *asnsFlag == "" {
		log.Fatal("Provide -countries or -asns")
	}

	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		log.Fatal(err)
	}

	start := time.Now()

	if *countriesFlag != "" {
		runCountryMode(strings.Split(*countriesFlag, ","), *workersFlag)
	}

	if *asnsFlag != "" {
		runASNMode(strings.Split(*asnsFlag, ","), *workersFlag)
	}

	fmt.Printf("\n[SUCCESS] Total time: %v\n", time.Since(start))
}

func runCountryMode(countries []string, workers int) {
	fmt.Printf("[*] Bulk Sync: %d countries, %d workers\n", len(countries), workers)
	ccChan := make(chan string, len(countries))
	for _, cc := range countries {
		ccChan <- strings.TrimSpace(strings.ToUpper(cc))
	}
	close(ccChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[int]float64)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 30 * time.Second}
			for cc := range ccChan {
				if cc == "" { continue }
				body, err := fetchURL(client, fmt.Sprintf("%s/%s", BaseURL, cc))
				if err != nil { continue }
				
				lines := strings.Split(string(body), "\n")
				found := 0
				for _, line := range lines {
					if !strings.Contains(line, ">AS") { continue }
					aMatch := asnRegex.FindStringSubmatch(line)
					sMatch := scoreRegex.FindStringSubmatch(line)
					if len(aMatch) >= 2 && len(sMatch) >= 2 {
						asn, _ := strconv.Atoi(aMatch[1])
						score, _ := strconv.ParseFloat(sMatch[1], 64)
						mu.Lock()
						if score > results[asn] { results[asn] = score }
						mu.Unlock()
						found++
					}
				}
				fmt.Printf("    - %s: Found %d ASNs\n", cc, found)
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	wg.Wait()

	fmt.Printf("[*] Updating files for %d ASNs...\n", len(results))
	for asn, score := range results {
		updateASNFile(asn, score)
	}
}

func runASNMode(asns []string, workers int) {
	fmt.Printf("[*] Targeted Sync: %d ASNs, %d workers\n", len(asns), workers)
	asnChan := make(chan int, len(asns))
	for _, s := range asns {
		if a, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			asnChan <- a
		}
	}
	close(asnChan)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 20 * time.Second}
			for asn := range asnChan {
				url := fmt.Sprintf("%s/AS%d?hf=1", BaseURL, asn)
				body, err := fetchURL(client, url)
				if err != nil { continue }

				var dataObj struct {
					Data []map[string]interface{} `json:"data"`
				}
				if err := json.Unmarshal(body, &dataObj); err != nil { continue }
				
				score := aggregateASNData(dataObj.Data)
				updateASNFile(asn, score)
				fmt.Printf("    - AS%d: %.1f%%\n", asn, score)
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

func fetchURL(client *http.Client, url string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func aggregateASNData(series []map[string]interface{}) float64 {
	if len(series) == 0 { return 0 }
	latestDate := ""
	for _, item := range series {
		if dt, ok := item["ras_dt"].(string); ok && dt > latestDate {
			latestDate = dt
		}
	}
	if latestDate == "" { return 0 }
	var valid, total float64
	for _, item := range series {
		if item["ras_dt"] == latestDate {
			if v, ok := item["ras_v4_val_robjs"].(float64); ok { valid += v }
			if t, ok := item["ras_v4_robjs"].(float64); ok { total += t }
		}
	}
	if total == 0 { return 0 }
	return (valid / total) * 100.0
}

func updateASNFile(asn int, score float64) {
	path := filepath.Join(OutputDir, fmt.Sprintf("as_%d.json", asn))
	data := make(map[string]interface{})
	if file, err := os.ReadFile(path); err == nil {
		json.Unmarshal(file, &data)
	}
	data["asn"] = asn
	data["roa_signed_pct"] = score
	data["roa_last_check"] = time.Now().UTC().Format(time.RFC3339)
	newData, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, newData, 0644)
}
