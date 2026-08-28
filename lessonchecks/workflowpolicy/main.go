package main

import (
	"encoding/json"
	"os"
	"strings"
)

const (
	workflowPath = ".github/workflows/go-checks.yml"
	checkoutStep = "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2"
	setupGoStep  = "      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0"
	testStep     = "      - run: go test ./..."
	vetStep      = "      - run: go vet ./..."
	vulnStep     = "      - run: go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./..."
)

type result struct {
	PushAndPullRequestTriggers  bool `json:"pushAndPullRequestTriggers"`
	ReadOnlyPermissions         bool `json:"readOnlyPermissions"`
	ActionsPinned               bool `json:"actionsPinned"`
	GoVersionAndCacheConfigured bool `json:"goVersionAndCacheConfigured"`
	SecurityChecksRun           bool `json:"securityChecksRun"`
}

func main() {
	workflowBytes, _ := os.ReadFile(workflowPath)
	lines := activeLines(string(workflowBytes))
	onBlock := namedBlock(lines, "on:")
	permissionsBlock := namedBlock(lines, "permissions:")
	jobsBlock := namedBlock(lines, "jobs:")
	testJob := namedBlock(jobsBlock, "  test:")

	checkoutIndex := lineIndex(testJob, checkoutStep)
	setupGoIndex := lineIndex(testJob, setupGoStep)
	testIndex := lineIndex(testJob, testStep)
	vetIndex := lineIndex(testJob, vetStep)
	vulnIndex := lineIndex(testJob, vulnStep)
	requiredSteps := []int{checkoutIndex, setupGoIndex, testIndex, vetIndex, vulnIndex}
	setupGoEnd := stepEnd(testJob, setupGoIndex)

	writeResult(result{
		PushAndPullRequestTriggers:  hasLine(onBlock, "  push:") && hasLine(onBlock, "  pull_request:") && !hasLine(onBlock, "  pull_request_target:"),
		ReadOnlyPermissions:         directLinesEqual(permissionsBlock, 2, []string{"  contents: read"}) && !hasIndentedKey(jobsBlock, 4, "permissions"),
		ActionsPinned:               checkoutIndex >= 0 && setupGoIndex >= 0 && allExternalActionsPinned(jobsBlock),
		GoVersionAndCacheConfigured: setupGoIndex >= 0 && hasLineBetween(testJob, setupGoIndex+1, setupGoEnd, "        with:") && hasLineBetween(testJob, setupGoIndex+1, setupGoEnd, "          go-version-file: go.mod") && hasLineBetween(testJob, setupGoIndex+1, setupGoEnd, "          cache-dependency-path: go.sum"),
		SecurityChecksRun:           hasLine(testJob, "    runs-on: ubuntu-latest") && !hasControl(testJob, 4) && indexesInOrder(requiredSteps) && stepsAreUnconditional(testJob, requiredSteps),
	})
}

func activeLines(contents string) []string {
	var lines []string
	for line := range strings.SplitSeq(strings.ReplaceAll(contents, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, strings.TrimRight(line, " \t"))
	}
	return lines
}

func namedBlock(lines []string, header string) []string {
	start := lineIndex(lines, header)
	if start < 0 {
		return nil
	}
	indent := leadingSpaces(header)
	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if leadingSpaces(lines[index]) <= indent {
			end = index
			break
		}
	}
	return lines[start+1 : end]
}

func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func lineIndex(lines []string, expected string) int {
	for index, line := range lines {
		if line == expected {
			return index
		}
	}
	return -1
}

func hasLine(lines []string, expected string) bool {
	return lineIndex(lines, expected) >= 0
}

func hasLineBetween(lines []string, start, end int, expected string) bool {
	if start < 0 || end < start {
		return false
	}
	return hasLine(lines[start:end], expected)
}

func directLinesEqual(lines []string, indent int, expected []string) bool {
	var direct []string
	for _, line := range lines {
		if leadingSpaces(line) == indent {
			direct = append(direct, line)
		}
	}
	return len(direct) == len(expected) && strings.Join(direct, "\n") == strings.Join(expected, "\n")
}

func hasIndentedKey(lines []string, indent int, key string) bool {
	prefix := strings.Repeat(" ", indent) + key + ":"
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func stepEnd(lines []string, start int) int {
	if start < 0 {
		return 0
	}
	for index := start + 1; index < len(lines); index++ {
		if leadingSpaces(lines[index]) == 6 && strings.HasPrefix(strings.TrimSpace(lines[index]), "- ") {
			return index
		}
	}
	return len(lines)
}

func stepsAreUnconditional(lines []string, indexes []int) bool {
	for _, index := range indexes {
		if index < 0 || hasControl(lines[index+1:stepEnd(lines, index)], 8) {
			return false
		}
	}
	return true
}

func hasControl(lines []string, indent int) bool {
	return hasIndentedKey(lines, indent, "if") || hasIndentedKey(lines, indent, "continue-on-error")
}

func indexesInOrder(indexes []int) bool {
	previous := -1
	for _, index := range indexes {
		if index <= previous {
			return false
		}
		previous = index
	}
	return true
}

func allExternalActionsPinned(lines []string) bool {
	for _, line := range lines {
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		code, _, _ := strings.Cut(text, "#")
		key, value, found := strings.Cut(strings.TrimSpace(code), ":")
		if !found || strings.TrimSpace(key) != "uses" {
			continue
		}
		action := strings.TrimSpace(value)
		if strings.HasPrefix(action, "./") {
			continue
		}
		_, reference, found := strings.Cut(action, "@")
		if !found || len(reference) != 40 || strings.Trim(reference, "0123456789abcdef") != "" {
			return false
		}
	}
	return true
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
