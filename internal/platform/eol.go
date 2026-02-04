// Package platform provides framework and platform detection capabilities.
package platform

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EOLInfo contains end-of-life information for a framework version
type EOLInfo struct {
	Framework   string    `json:"framework"`
	Version     string    `json:"version"`
	EOLDate     time.Time `json:"eol_date"`
	IsEOL       bool      `json:"is_eol"`
	DaysUntilEOL int      `json:"days_until_eol,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	UpgradePath   string `json:"upgrade_path,omitempty"`
	Severity      string  `json:"severity"`
	CVSS          float64 `json:"cvss"`
}

// EOLChecker checks framework versions against EOL databases
type EOLChecker struct {
	eolDatabase map[string]EOLData
}

// EOLData contains EOL information for a framework
type EOLData struct {
	Framework     string
	LatestVersion string
	Versions      []VersionEOL
}

// VersionEOL contains EOL info for a specific version
type VersionEOL struct {
	Version   string
	EOLDate   time.Time
	LTS       bool
	Supported bool
}

// NewEOLChecker creates a new EOL checker
func NewEOLChecker() *EOLChecker {
	checker := &EOLChecker{
		eolDatabase: make(map[string]EOLData),
	}
	checker.initializeDatabase()
	return checker
}

// initializeDatabase sets up the EOL database
func (e *EOLChecker) initializeDatabase() {
	// React EOL data
	e.eolDatabase["React"] = EOLData{
		Framework:     "React",
		LatestVersion: "18.2.0",
		Versions: []VersionEOL{
			{Version: "0.x", EOLDate: time.Date(2017, 9, 26, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "15.x", EOLDate: time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "16.x", EOLDate: time.Date(2022, 3, 29, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "17.x", EOLDate: time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "18.x", Supported: true},
		},
	}

	// Vue.js EOL data
	e.eolDatabase["Vue.js"] = EOLData{
		Framework:     "Vue.js",
		LatestVersion: "3.4.0",
		Versions: []VersionEOL{
			{Version: "1.x", EOLDate: time.Date(2017, 9, 27, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "2.x", EOLDate: time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "2.7", EOLDate: time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC), LTS: true, Supported: false},
			{Version: "3.x", Supported: true},
		},
	}

	// Angular EOL data
	e.eolDatabase["Angular"] = EOLData{
		Framework:     "Angular",
		LatestVersion: "17.0.0",
		Versions: []VersionEOL{
			{Version: "2.x", EOLDate: time.Date(2018, 3, 23, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "4.x", EOLDate: time.Date(2018, 9, 18, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "5.x", EOLDate: time.Date(2019, 5, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "6.x", EOLDate: time.Date(2019, 11, 28, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "7.x", EOLDate: time.Date(2020, 4, 18, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "8.x", EOLDate: time.Date(2020, 11, 28, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "9.x", EOLDate: time.Date(2021, 8, 6, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "10.x", EOLDate: time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "11.x", EOLDate: time.Date(2022, 5, 11, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "12.x", EOLDate: time.Date(2022, 11, 12, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "13.x", EOLDate: time.Date(2023, 5, 4, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "14.x", EOLDate: time.Date(2023, 11, 18, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "15.x", EOLDate: time.Date(2024, 5, 15, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "16.x", EOLDate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "17.x", Supported: true},
		},
	}

	// Node.js EOL data (commonly used)
	e.eolDatabase["Node.js"] = EOLData{
		Framework:     "Node.js",
		LatestVersion: "21.0.0",
		Versions: []VersionEOL{
			{Version: "10.x", EOLDate: time.Date(2021, 4, 30, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "12.x", EOLDate: time.Date(2022, 4, 30, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "14.x", EOLDate: time.Date(2023, 4, 30, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "15.x", EOLDate: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "16.x", EOLDate: time.Date(2023, 9, 11, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "17.x", EOLDate: time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "18.x", EOLDate: time.Date(2025, 4, 30, 0, 0, 0, 0, time.UTC), LTS: true, Supported: true},
			{Version: "19.x", EOLDate: time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "20.x", EOLDate: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC), LTS: true, Supported: true},
			{Version: "21.x", Supported: true},
		},
	}

	// jQuery EOL data
	e.eolDatabase["jQuery"] = EOLData{
		Framework:     "jQuery",
		LatestVersion: "3.7.1",
		Versions: []VersionEOL{
			{Version: "1.x", EOLDate: time.Date(2014, 1, 24, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "2.x", EOLDate: time.Date(2016, 5, 20, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "3.x", Supported: true},
		},
	}

	// Bootstrap EOL data
	e.eolDatabase["Bootstrap"] = EOLData{
		Framework:     "Bootstrap",
		LatestVersion: "5.3.2",
		Versions: []VersionEOL{
			{Version: "2.x", EOLDate: time.Date(2013, 8, 19, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "3.x", EOLDate: time.Date(2019, 7, 24, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "4.x", EOLDate: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC), Supported: false},
			{Version: "5.x", Supported: true},
		},
	}
}

// CheckEOL checks if a framework version is EOL
func (e *EOLChecker) CheckEOL(framework, version string) *EOLInfo {
	eolData, ok := e.eolDatabase[framework]
	if !ok {
		return nil
	}

	// Extract major version
	majorVersion := extractMajorVersion(version)

	// Check each version pattern
	for _, v := range eolData.Versions {
		if strings.HasPrefix(majorVersion+".", v.Version) || majorVersion+".x" == v.Version {
			info := &EOLInfo{
				Framework:     framework,
				Version:       version,
				EOLDate:       v.EOLDate,
				LatestVersion: eolData.LatestVersion,
			}

			if !v.Supported {
				info.IsEOL = true
				daysSinceEOL := int(time.Since(v.EOLDate).Hours() / 24)
				info.DaysUntilEOL = -daysSinceEOL

				// Determine severity based on how long it's been EOL
				if daysSinceEOL > 365 {
					info.Severity = "HIGH"
					info.CVSS = 7.5
				} else if daysSinceEOL > 180 {
					info.Severity = "MEDIUM"
					info.CVSS = 5.5
				} else {
					info.Severity = "LOW"
					info.CVSS = 3.5
				}

				info.UpgradePath = fmt.Sprintf("Upgrade to %s", eolData.LatestVersion)
			} else {
				info.IsEOL = false
				if !v.EOLDate.IsZero() {
					daysUntil := int(v.EOLDate.Sub(time.Now()).Hours() / 24)
					info.DaysUntilEOL = daysUntil
				}
			}

			return info
		}
	}

	return nil
}

// CheckDetection checks all frameworks in a detection
func (e *EOLChecker) CheckDetection(detection *Detection) []EOLInfo {
	var results []EOLInfo

	for _, fw := range detection.Frameworks {
		if fw.Version != "" {
			if info := e.CheckEOL(fw.Name, fw.Version); info != nil {
				results = append(results, *info)
			}
		}
	}

	return results
}

// GetAllEOLFrameworks returns list of frameworks with EOL data
func (e *EOLChecker) GetAllEOLFrameworks() []string {
	var frameworks []string
	for name := range e.eolDatabase {
		frameworks = append(frameworks, name)
	}
	return frameworks
}

// extractMajorVersion extracts major version (x.y.z -> x.y)
func extractMajorVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

// parseVersion parses version string to comparable numbers
func parseVersion(version string) []int {
	parts := strings.Split(version, ".")
	var nums []int
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			nums = append(nums, n)
		}
	}
	return nums
}

// versionGreaterOrEqual compares versions
func versionGreaterOrEqual(v1, v2 []int) bool {
	for i := 0; i < len(v1) && i < len(v2); i++ {
		if v1[i] > v2[i] {
			return true
		}
		if v1[i] < v2[i] {
			return false
		}
	}
	return len(v1) >= len(v2)
}