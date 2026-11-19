package diffparse

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

var ticketRegex = regexp.MustCompile(`\b((?:CHG|JIRA)-[0-9]+)\b`)

// Metadata represents pipeline / PR context surrounding a git diff.
type Metadata struct {
	Author        string `json:"author"`
	Branch        string `json:"branch"`
	ChangeTicket  string `json:"changeTicket"`
	CommitMessage string `json:"commitMessage"`
}

// Summary aggregates metrics across all changed files in the diff.
type Summary struct {
	TotalFiles     int      `json:"totalFiles"`
	TotalAdded     int      `json:"totalAdded"`
	TotalRemoved   int      `json:"totalRemoved"`
	HasProdChanges bool     `json:"hasProdChanges"`
	Environments   []string `json:"environments"`
}

// FileDiff represents the parsed diff for a single file.
type FileDiff struct {
	OldPath      string   `json:"oldPath"`
	NewPath      string   `json:"newPath"`
	Path         string   `json:"path"`
	ChangeType   string   `json:"changeType"`
	Environment  string   `json:"environment"`
	AddedLines   []string `json:"addedLines"`
	RemovedLines []string `json:"removedLines"`
	AddedText    string   `json:"addedText"`
	RemovedText  string   `json:"removedText"`
}

// DiffReport is the structured JSON-friendly representation of a unified git diff.
type DiffReport struct {
	Metadata Metadata   `json:"metadata"`
	Summary  Summary    `json:"summary"`
	Files    []FileDiff `json:"files"`
}

// Parse converts a unified git diff (plus optional metadata) into a structured DiffReport.
func Parse(rawDiff string, meta Metadata) DiffReport {
	if meta.ChangeTicket == "" && meta.CommitMessage != "" {
		if m := ticketRegex.FindStringSubmatch(meta.CommitMessage); len(m) > 1 {
			meta.ChangeTicket = m[1]
		}
	}

	lines := strings.Split(strings.ReplaceAll(rawDiff, "\r\n", "\n"), "\n")
	var files []FileDiff
	var current *FileDiff
	inHunk := false

	flush := func() {
		if current == nil {
			return
		}
		if current.Path == "" {
			if current.NewPath != "" && current.NewPath != "/dev/null" {
				current.Path = current.NewPath
			} else {
				current.Path = current.OldPath
			}
		}
		current.Environment = detectEnvironment(current.Path)
		current.AddedText = strings.Join(current.AddedLines, "\n")
		current.RemovedText = strings.Join(current.RemovedLines, "\n")
		if current.AddedLines == nil {
			current.AddedLines = []string{}
		}
		if current.RemovedLines == nil {
			current.RemovedLines = []string{}
		}
		files = append(files, *current)
		current = nil
		inHunk = false
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			oldP, newP := parseDiffHeaderPaths(line)
			current = &FileDiff{
				OldPath:    oldP,
				NewPath:    newP,
				Path:       newP,
				ChangeType: "modified",
			}
			continue
		}

		if current == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "new file mode "):
			current.ChangeType = "added"
		case strings.HasPrefix(line, "deleted file mode "):
			current.ChangeType = "deleted"
		case strings.HasPrefix(line, "rename to "):
			current.ChangeType = "renamed"
			current.NewPath = strings.TrimSpace(strings.TrimPrefix(line, "rename to "))
			current.Path = current.NewPath
		case strings.HasPrefix(line, "--- "):
			p := cleanHeaderPath(strings.TrimPrefix(line, "--- "))
			if p == "/dev/null" {
				current.ChangeType = "added"
			} else if p != "" {
				current.OldPath = p
			}
		case strings.HasPrefix(line, "+++ "):
			p := cleanHeaderPath(strings.TrimPrefix(line, "+++ "))
			if p == "/dev/null" {
				current.ChangeType = "deleted"
				current.Path = current.OldPath
			} else if p != "" {
				current.NewPath = p
				current.Path = p
			}
		case strings.HasPrefix(line, "@@ "):
			inHunk = true
		case inHunk && strings.HasPrefix(line, "+"):
			current.AddedLines = append(current.AddedLines, strings.TrimPrefix(line, "+"))
		case inHunk && strings.HasPrefix(line, "-"):
			current.RemovedLines = append(current.RemovedLines, strings.TrimPrefix(line, "-"))
		}
	}
	flush()

	envSet := map[string]struct{}{}
	totalAdded, totalRemoved := 0, 0
	hasProd := false
	for _, f := range files {
		totalAdded += len(f.AddedLines)
		totalRemoved += len(f.RemovedLines)
		if f.Environment == "prod" {
			hasProd = true
		}
		envSet[f.Environment] = struct{}{}
	}

	envs := make([]string, 0, len(envSet))
	for e := range envSet {
		envs = append(envs, e)
	}
	sort.Strings(envs)

	if files == nil {
		files = []FileDiff{}
	}

	return DiffReport{
		Metadata: meta,
		Summary: Summary{
			TotalFiles:     len(files),
			TotalAdded:     totalAdded,
			TotalRemoved:   totalRemoved,
			HasProdChanges: hasProd,
			Environments:   envs,
		},
		Files: files,
	}
}

// ToMap converts the DiffReport to generic JSON structures (map[string]any / []any)
// expected by kyverno-json and JMESPath evaluators.
func (r DiffReport) ToMap() (map[string]any, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseDiffHeaderPaths(line string) (string, string) {
	fields := strings.Fields(strings.TrimPrefix(line, "diff --git "))
	if len(fields) < 2 {
		return "", ""
	}
	return strings.TrimPrefix(fields[0], "a/"), strings.TrimPrefix(fields[1], "b/")
}

func cleanHeaderPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "/dev/null" {
		return raw
	}
	raw = strings.TrimPrefix(raw, "a/")
	raw = strings.TrimPrefix(raw, "b/")
	return raw
}

func detectEnvironment(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/prod/") || strings.HasPrefix(lower, "environments/prod/") || strings.HasPrefix(lower, "prod/"):
		return "prod"
	case strings.Contains(lower, "/staging/") || strings.HasPrefix(lower, "environments/staging/") || strings.HasPrefix(lower, "staging/"):
		return "staging"
	case strings.Contains(lower, "/dev/") || strings.HasPrefix(lower, "environments/dev/") || strings.HasPrefix(lower, "dev/"):
		return "dev"
	default:
		return "unknown"
	}
}
