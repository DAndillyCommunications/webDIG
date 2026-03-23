package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// GeoData matches the IP-API response
type GeoData struct {
	Status  string `json:"status"`
	Isp     string `json:"isp"`
	Org     string `json:"org"`
	As      string `json:"as"`
	City    string `json:"city"`
	Country string `json:"country"`
}

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Deep Edge Diagnostic Tool v1.0")
	window.Resize(fyne.NewSize(600, 500))

	input := widget.NewEntry()
	input.SetPlaceHolder("Enter domain (e.g., google.com)")

	output := widget.NewMultiLineEntry()
	output.Disable() // This replaces SetReadOnly
	output.Wrapping = fyne.TextWrapWord

	statusLabel := widget.NewLabel("Ready")

	runDiagnostic := func() {
		domain := strings.TrimSpace(input.Text)
		if domain == "" {
			statusLabel.SetText("Please enter a domain!")
			return
		}

		statusLabel.SetText("Diagnosing: " + domain + "...")
		output.SetText("Working...")

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("--- DIAGNOSTIC FOR: %s ---\n\n", domain))

		// 1. IP & ASN Info
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			sb.WriteString("[!] Failed to resolve IP.\n")
		} else {
			targetIP := ips[0].String()
			sb.WriteString(fmt.Sprintf("[*] IPv4 Address: %s\n", targetIP))

			client := &http.Client{Timeout: 3 * time.Second}
			apiResp, err := client.Get("http://ip-api.com/json/" + targetIP)
			if err == nil {
				var geo GeoData
				json.NewDecoder(apiResp.Body).Decode(&geo)
				apiResp.Body.Close()
				if geo.Status == "success" {
					sb.WriteString(fmt.Sprintf("    ISP: %s\n", geo.Isp))
					sb.WriteString(fmt.Sprintf("    Org: %s\n", geo.Org))
					sb.WriteString(fmt.Sprintf("    ASN: %s\n", geo.As))
					sb.WriteString(fmt.Sprintf("    Location: %s, %s\n", geo.City, geo.Country))
				}
			}
		}

		// 2. Nameservers
		nsRecords, _ := net.LookupNS(domain)
		if len(nsRecords) > 0 {
			sb.WriteString("\n[*] Nameservers:\n")
			for _, r := range nsRecords {
				sb.WriteString(fmt.Sprintf("  - %s\n", r.Host))
			}
		}

		// 3. HTTP Headers
		sb.WriteString("\n[*] Edge & Header Inspection:\n")
		headerClient := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("HEAD", "https://"+domain, nil)
		hResp, err := headerClient.Do(req)

		if err != nil {
			sb.WriteString("[!] HTTP Request failed (HTTPS may be blocked).\n")
		} else {
			defer hResp.Body.Close()
			sb.WriteString(fmt.Sprintf("  Server Type: %s\n", hResp.Header.Get("Server")))

			if hResp.Header.Get("CF-Ray") != "" {
				sb.WriteString("  [!] CLOUDFLARE DETECTED\n")
				sb.WriteString(fmt.Sprintf("  CF-Ray ID: %s\n", hResp.Header.Get("CF-Ray")))
			} else if hResp.Header.Get("X-Amz-Cf-Id") != "" {
				sb.WriteString("  [!] AWS CLOUDFRONT DETECTED\n")
			}
		}

		output.SetText(sb.String())
		statusLabel.SetText("Done.")
	}

	form := container.NewVBox(
		widget.NewLabel("Target Domain:"),
		input,
		widget.NewButton("Run Diagnostic", runDiagnostic),
		statusLabel,
	)

	window.SetContent(container.NewBorder(form, nil, nil, nil, container.NewScroll(output)))
	window.ShowAndRun()
}