package main

import "time"

type SnykDTO struct {
	Vulnerabilities    []Vulnerabilities `json:"vulnerabilities"`
	Ok                 bool              `json:"ok"`
	DependencyCount    int               `json:"dependencyCount"`
	Org                string            `json:"org"`
	Policy             string            `json:"policy"`
	IsPrivate          bool              `json:"isPrivate"`
	LicensesPolicy     LicensesPolicy    `json:"licensesPolicy"`
	PackageManager     string            `json:"packageManager"`
	IgnoreSettings     IgnoreSettings    `json:"ignoreSettings"`
	Docker             Docker            `json:"docker"`
	Summary            string            `json:"summary"`
	FilesystemPolicy   bool              `json:"filesystemPolicy"`
	Filtered           Filtered          `json:"filtered"`
	UniqueCount        int               `json:"uniqueCount"`
	ProjectName        string            `json:"projectName"`
	Platform           string            `json:"platform"`
	HasUnknownVersions bool              `json:"hasUnknownVersions"`
	Path               string            `json:"path"`
}
type Semver struct {
	Vulnerable []string `json:"vulnerable"`
}
type Insights struct {
	TriageAdvice interface{} `json:"triageAdvice"`
}
type References struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}
type CvssDetails struct {
	Assigner         string    `json:"assigner"`
	Severity         string    `json:"severity"`
	CvssV3Vector     string    `json:"cvssV3Vector"`
	CvssV3BaseScore  float64   `json:"cvssV3BaseScore"`
	ModificationTime time.Time `json:"modificationTime"`
}
type Identifiers struct {
	Cve         []string      `json:"CVE"`
	Cwe         []string      `json:"CWE"`
	Alternative []interface{} `json:"ALTERNATIVE"`
}
type Vulnerabilities struct {
	ID                    string        `json:"id"`
	Cpes                  []interface{} `json:"cpes"`
	Title                 string        `json:"title"`
	CVSSv3                string        `json:"CVSSv3"`
	Credit                []string      `json:"credit"`
	Semver                Semver        `json:"semver"`
	Exploit               string        `json:"exploit"`
	Patches               []interface{} `json:"patches"`
	Insights              Insights      `json:"insights"`
	Language              string        `json:"language"`
	Severity              string        `json:"severity"`
	CvssScore             float64       `json:"cvssScore"`
	Malicious             bool          `json:"malicious"`
	References            []References  `json:"references"`
	CvssDetails           []CvssDetails `json:"cvssDetails"`
	Description           string        `json:"description"`
	Identifiers           Identifiers   `json:"identifiers"`
	NvdSeverity           string        `json:"nvdSeverity"`
	PackageName           string        `json:"packageName"`
	CreationTime          time.Time     `json:"creationTime"`
	DisclosureTime        time.Time     `json:"disclosureTime"`
	PackageManager        string        `json:"packageManager"`
	PublicationTime       time.Time     `json:"publicationTime"`
	ModificationTime      time.Time     `json:"modificationTime"`
	SocialTrendAlert      bool          `json:"socialTrendAlert"`
	RelativeImportance    string        `json:"relativeImportance"`
	SeverityWithCritical  string        `json:"severityWithCritical"`
	From                  []string      `json:"from"`
	UpgradePath           []interface{} `json:"upgradePath"`
	IsUpgradable          bool          `json:"isUpgradable"`
	IsPatchable           bool          `json:"isPatchable"`
	Name                  string        `json:"name"`
	Version               string        `json:"version"`
	DockerBaseImage       string        `json:"dockerBaseImage"`
	NearestFixedInVersion string        `json:"nearestFixedInVersion,omitempty"`
	DockerfileInstruction string        `json:"dockerfileInstruction,omitempty"`
}
type Severities struct {
}
type AGPL10 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type AGPL30 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type Artistic10 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type Artistic20 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type CDDL10 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type CPOL102 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type EPL10 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type GPL20 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type GPL30 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type LGPL20 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type LGPL21 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type LGPL30 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type MPL11 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type MPL20 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type MSRL struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type SimPL20 struct {
	LicenseType  string `json:"licenseType"`
	Severity     string `json:"severity"`
	Instructions string `json:"instructions"`
}
type OrgLicenseRules struct {
	AGPL10     AGPL10     `json:"AGPL-1.0"`
	AGPL30     AGPL30     `json:"AGPL-3.0"`
	Artistic10 Artistic10 `json:"Artistic-1.0"`
	Artistic20 Artistic20 `json:"Artistic-2.0"`
	CDDL10     CDDL10     `json:"CDDL-1.0"`
	CPOL102    CPOL102    `json:"CPOL-1.02"`
	EPL10      EPL10      `json:"EPL-1.0"`
	GPL20      GPL20      `json:"GPL-2.0"`
	GPL30      GPL30      `json:"GPL-3.0"`
	LGPL20     LGPL20     `json:"LGPL-2.0"`
	LGPL21     LGPL21     `json:"LGPL-2.1"`
	LGPL30     LGPL30     `json:"LGPL-3.0"`
	MPL11      MPL11      `json:"MPL-1.1"`
	MPL20      MPL20      `json:"MPL-2.0"`
	MSRL       MSRL       `json:"MS-RL"`
	SimPL20    SimPL20    `json:"SimPL-2.0"`
}
type LicensesPolicy struct {
	Severities      Severities      `json:"severities"`
	OrgLicenseRules OrgLicenseRules `json:"orgLicenseRules"`
}
type IgnoreSettings struct {
	AdminOnly                  bool `json:"adminOnly"`
	ReasonRequired             bool `json:"reasonRequired"`
	DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
}
type Advice struct {
	Message string `json:"message"`
	Bold    bool   `json:"bold,omitempty"`
}
type BaseImageRemediation struct {
	Code   string   `json:"code"`
	Advice []Advice `json:"advice"`
}
type IssuesData struct {
}
type AffectedPkgs struct {
}
type BinariesVulns struct {
	IssuesData   IssuesData   `json:"issuesData"`
	AffectedPkgs AffectedPkgs `json:"affectedPkgs"`
}
type Docker struct {
	BaseImage            string               `json:"baseImage"`
	BaseImageRemediation BaseImageRemediation `json:"baseImageRemediation"`
	BinariesVulns        BinariesVulns        `json:"binariesVulns"`
}
type Filtered struct {
	Ignore []interface{} `json:"ignore"`
	Patch  []interface{} `json:"patch"`
}
