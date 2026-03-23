package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"image/color"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
//	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/jung-kurt/gofpdf"
)

// -------------------- DATA --------------------

type Result struct {
	Domain    string   `json:"domain"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	DualStack bool     `json:"dual_stack"`
	ASN       string   `json:"asn"`
	Org       string   `json:"org"`
	CDN       string   `json:"cdn"`
	Peering   string   `json:"peering"`
}

var lastResults []Result

// -------------------- MAIN --------------------

func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(&customTheme{})

	window := myApp.NewWindow("Deep Edge ISP Tool v5")
	window.Resize(fyne.NewSize(900, 700))

	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("Enter domains (one per line)")

	output := widget.NewMultiLineEntry()
	output.Disable()
	output.Wrapping = fyne.TextWrapWord

	status := widget.NewLabel("Ready")
	progress := widget.NewProgressBar()

	// ---------------- RUN BATCH ----------------
	runBtn := widget.NewButton("Run Analysis", nil)
	runBtn.OnTapped = func() {
		domains := cleanDomains(input.Text)
		if len(domains) == 0 {
			status.SetText("Error: Please enter domains.")
			return
		}

		runBtn.Disable()
		progress.SetValue(0)
		status.SetText("Running analysis...")
		output.SetText("")

		go func() {
			results := runBatch(domains, progress)
			lastResults = results

			var sb strings.Builder
			for _, r := range results {
				ds := "No"
				if r.DualStack {
					ds = "Yes"
				}
				sb.WriteString(fmt.Sprintf("%s | IPv6: %s | ASN: %s | %s | %s\n", r.Domain, ds, r.ASN, r.Org, r.CDN))
			}

			output.SetText(sb.String())
			status.SetText("Done. Ready to export.")
			runBtn.Enable()
		}()
	}

	// ---------------- EXPORTS ----------------
	pdfBtn := widget.NewButton("Export PDF", func() {
		if len(lastResults) == 0 { return }
		generatePDF(lastResults)
		status.SetText("Exported report.pdf")
	})

	csvExportBtn := widget.NewButton("Export CSV", func() {
		if len(lastResults) == 0 { return }
		exportCSV(lastResults)
		status.SetText("Exported results.csv")
	})

	jsonBtn := widget.NewButton("Export JSON", func() {
		if len(lastResults) == 0 { return }
		exportJSON(lastResults)
		status.SetText("Exported results.json")
	})

	// ---------------- LAYOUT ----------------
	ui := container.NewVBox(
		widget.NewLabel("Target Domains:"),
		input,
		container.NewHBox(runBtn, pdfBtn, csvExportBtn, jsonBtn),
		progress,
		status,
	)

	window.SetContent(container.NewBorder(ui, nil, nil, nil, container.NewScroll(output)))
	window.ShowAndRun()
}

// ---------------- CORE LOGIC ----------------

func cleanDomains(text string) []string {
	lines := strings.Split(text, "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" { out = append(out, l) }
	}
	return out
}

func runBatch(domains []string, progress *widget.ProgressBar) []Result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []Result
	total := len(domains)
	completed := 0

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			res := analyzeDomain(domain)
			mu.Lock()
			results = append(results, res)
			completed++
			progress.SetValue(float64(completed) / float64(total))
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return results
}

func analyzeDomain(domain string) Result {
	res := Result{Domain: domain, ASN: "Unknown", Org: "Unknown", CDN: "Unknown", Peering: "Unknown"}

	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		if ip.To4() != nil {
			res.IPv4 = append(res.IPv4, ip.String())
		} else {
			res.IPv6 = append(res.IPv6, ip.String())
		}
	}

	res.DualStack = len(res.IPv4) > 0 && len(res.IPv6) > 0

	if len(res.IPv4) > 0 {
		asn, org := lookupASN(res.IPv4[0])
		res.ASN = asn
		res.Org = org
		res.CDN = detectCDN(domain)
		res.Peering = lookupPeering(asn)
	}
	return res
}

// ---------------- APIS (Mocks/Basics) ----------------

func lookupASN(ip string) (string, string) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil { return "Unknown", "Unknown" }
	defer resp.Body.Close()

	var data struct { As, Org string }
	json.NewDecoder(resp.Body).Decode(&data)
	if data.As == "" { return "Unknown", "Unknown" }
	return data.As, data.Org
}

func detectCDN(domain string) string {
	client := http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("HEAD", "https://"+domain, nil)
	resp, err := client.Do(req)
	if err != nil { return "Unknown" }
	defer resp.Body.Close()

	h := resp.Header
	if h.Get("CF-Ray") != "" { return "Cloudflare" }
	if h.Get("X-Amz-Cf-Id") != "" { return "AWS" }
	return "Unknown"
}

func lookupPeering(asn string) string {
	return "Open" // Simplified for brevity in this snippet
}

// ---------------- EXPORTERS ----------------

func exportCSV(results []Result) {
	file, _ := os.Create("results.csv")
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Domain", "IPv4", "IPv6", "DualStack", "ASN", "Org", "CDN", "Peering"})
	for _, r := range results {
		ds := "False"
		if r.DualStack { ds = "True" }
		writer.Write([]string{
			r.Domain, strings.Join(r.IPv4, ";"), strings.Join(r.IPv6, ";"),
			ds, r.ASN, r.Org, r.CDN, r.Peering,
		})
	}
}

func exportJSON(results []Result) {
	file, _ := os.Create("results.json")
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)
}

func generatePDF(results []Result) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "ISP Report")
	pdf.OutputFileAndClose("report.pdf")
}

// ---------------- THEME ----------------
type customTheme struct{}
func (c *customTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNameForeground {
		if v == theme.VariantDark { return color.White }
		return color.Black
	}
	return theme.DefaultTheme().Color(n, v)
}
func (c *customTheme) Font(s fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(s) }
func (c *customTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (c *customTheme) Size(n fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(n) }