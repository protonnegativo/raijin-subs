// Package subfinder runs the ProjectDiscovery subfinder binary and parses its output.
package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the subfinder binary is not on PATH.
var ErrNotFound = errors.New("subfinder binary not found")

// Result is one subdomain subfinder found: the name, the root domain it was found for and the passive
// sources that returned it (with -cs).
type Result struct {
	Host    string   `json:"host"`
	Input   string   `json:"input"`
	Sources []string `json:"sources"`
	Source  string   `json:"source"`
}

// Options are the subfinder settings Raijin passes through.
type Options struct {
	Binary  string
	Timeout int // seconds per source request (-timeout)
	MaxTime int // minutes for the whole enumeration (-max-time)
	Extra   []string
	// Raw, if set, receives subfinder's JSONL output unchanged.
	Raw io.Writer
	// Stats, if set, counts the output lines and the ones without the fields Raijin reads.
	Stats *Stats
}

// Stats counts subfinder's output lines: Bad have no "host" (or are not JSON), Unparsed are the bad
// lines that gave no result either.
type Stats struct {
	Lines, Bad, Unparsed int
}

// Fields are the fields every subfinder result must have.
const Fields = "host"

// Run enumerates the root domains and returns every result, plus the last stderr lines if subfinder failed.
func Run(ctx context.Context, roots []string, opt Options) ([]Result, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "subfinder"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-subs-roots-*.txt")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(roots, "\n")+"\n"); err != nil {
		list.Close()
		return nil, "", err
	}
	list.Close()

	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = stdout
	if opt.Raw != nil {
		r = io.TeeReader(stdout, opt.Raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	results, parseErr := parse(r, opt.Stats)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return results, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return results, tail(stderr.String(), 3), fmt.Errorf("subfinder exited: %w", waitErr)
	}
	return results, "", nil
}

// Args builds the subfinder command line. -cs lists every passive source that returned a name.
func Args(listFile string, opt Options) []string {
	args := []string{"-dL", listFile, "-json", "-cs", "-silent", "-nc", "-duc"}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	if opt.MaxTime > 0 {
		args = append(args, "-max-time", fmt.Sprint(opt.MaxTime))
	}
	return append(args, opt.Extra...)
}

// Parse reads subfinder output: JSONL lines ({"host": ...}) or plain lines with one name each (its text
// output). JSON lines from dnsx (they carry "status_code" or "resolver") are skipped, so a file with both
// engines' output can be read by both parsers.
func Parse(r io.Reader) ([]Result, error) {
	return parse(r, nil)
}

func parse(r io.Reader, st *Stats) ([]Result, error) {
	if st == nil {
		st = &Stats{}
	}
	var results []Result
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		st.Lines++
		if line[0] != '{' {
			st.Bad++
			if name := string(line); strings.Contains(name, ".") && !strings.ContainsAny(name, " \t[]{}\"") {
				results = append(results, Result{Host: name})
			} else {
				st.Unparsed++
			}
			continue
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			st.Bad++
			st.Unparsed++
			continue
		}
		if _, ok := probe["status_code"]; ok {
			continue
		}
		if _, ok := probe["resolver"]; ok {
			continue
		}
		var res Result
		if err := json.Unmarshal(line, &res); err != nil || res.Host == "" {
			st.Bad++
			st.Unparsed++
			continue
		}
		if len(res.Sources) == 0 && res.Source != "" {
			res.Sources = []string{res.Source}
		}
		res.Source = ""
		results = append(results, res)
	}
	return results, sc.Err()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
