package main

// Deep Edge ISP Intelligence Tool v3 (Fyne GUI + ISP Engine)

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/jung-kurt/gofpdf"
)

// -------------------- DATA STRUCTURES --------------------

type Result struct {
	Domain string
	IPs    []string
	ASN    string
	Org    string
	CDN    string
}

// -------------------- MAIN --------------------

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Deep Edge ISP Tool v3")
	window.Resize(fyne.NewSize(700, 600))

	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("Enter domains (one per line)")

	output := widget.NewMultiLineEntry()
	output.Disable()
	output.Wrapping = fyne.TextWrapWord

	status := widget.NewLabel("Ready")

	run := func() {
		domains := strings.Split(input.Text, "\n")
		var clean []string
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d != "" {
				clean = append(clean, d)
			}
		}

		status.SetText("Running analysis...")
		results := runBatch(clean)
		agg := aggregateASN(results)

		generatePDF(results, agg)

		var sb strings.Builder
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("%s | %s | %s | %s\n", r.Domain, r.ASN, r.Org, r.CDN))
		}

		output.SetText(sb.String())
		status.SetText("Done. PDF generated.")
	}

	ui := container.NewVBox(
		widget.NewLabel("Domains:"),
		input,
		widget.NewButton("Run Analysis + Generate PDF", run),
		status,
	)

	window.SetContent(container.NewBorder(ui, nil, nil, nil, container.NewScroll(output)))
	window.ShowAndRun()
}

// -------------------- BATCH --------------------

func runBatch(domains []string) []Result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []Result

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			res := analyzeDomain(domain)

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(d)
	}

	wg.Wait()
	return results
}

// -------------------- ANALYSIS --------------------

func analyzeDomain(domain string) Result {
	res := Result{Domain: domain}

	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		if ip.To4() != nil {
			res.IPs = append(res.IPs, ip.String())
		}
	}

	if len(res.IPs) > 0 {
		asn, org := lookupASN(res.IPs[0])
		res.ASN = asn
		res.Org = org
		res.CDN = detectCDN(domain)
	}

	return res
}

// -------------------- ASN --------------------

func lookupASN(ip string) (string, string) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return "Unknown", "Unknown"
	}
	defer resp.Body.Close()

	var data struct {
		As  string `json:"as"`
		Org string `json:"org"`
	}

	json.NewDecoder(resp.Body).Decode(&data)
	return data.As, data.Org
}

// -------------------- CDN --------------------

func detectCDN(domain string) string {
	client := http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("HEAD", "https://"+domain, nil)
	resp, err := client.Do(req)

	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	headers := resp.Header

	switch {
	case headers.Get("CF-Ray") != "":
		return "Cloudflare"
	case headers.Get("X-Amz-Cf-Id") != "":
		return "AWS CloudFront"
	case strings.Contains(headers.Get("Server"), "Google"):
		return "Google Cloud"
	default:
		return "Unknown"
	}
}

// -------------------- AGG --------------------

func aggregateASN(results []Result) map[string]int {
	agg := make(map[string]int)
	for _, r := range results {
		agg[r.ASN]++
	}
	return agg
}

// -------------------- PDF --------------------

func generatePDF(results []Result, agg map[string]int) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Deep Edge ISP Report")

	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Domains: %d", len(results)))

	pdf.Ln(10)
	pdf.Cell(40, 10, "ASN Summary:")
	pdf.Ln(8)

	for asn, count := range agg {
		pdf.Cell(40, 8, fmt.Sprintf("%s -> %d", asn, count))
		pdf.Ln(6)
	}

	pdf.AddPage()
	pdf.Cell(40, 10, "Details:")
	pdf.Ln(10)

	for _, r := range results {
		pdf.Cell(40, 8, "Domain: "+r.Domain)
		pdf.Ln(6)
		pdf.Cell(40, 8, "ASN: "+r.ASN)
		pdf.Ln(6)
		pdf.Cell(40, 8, "Org: "+r.Org)
		pdf.Ln(6)
		pdf.Cell(40, 8, "CDN: "+r.CDN)
		pdf.Ln(6)
		pdf.Cell(40, 8, "IPs: "+strings.Join(r.IPs, ", "))
		pdf.Ln(10)
	}

	pdf.OutputFileAndClose("report.pdf")
}
