// Package dnsx runs the ProjectDiscovery dnsx binary and parses its JSONL output.
package dnsx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the dnsx binary is not on PATH.
var ErrNotFound = errors.New("dnsx binary not found")

// ProbePrefix starts the random names raijin-subs resolves to detect wildcard DNS
// ("raijin-wc-1a2b3c4d.example.com"). They are not results: the reducer reads them only to decide which
// parents answer for any name, so a saved run replays with the same wildcard decisions.
const ProbePrefix = "raijin-wc-"

// Record is the subset of a dnsx JSONL result that Raijin uses: the DNS status and the A, AAAA and
// CNAME answers. CNAME is the chain in the order the resolver returned it.
type Record struct {
	Host       string   `json:"host"`
	StatusCode string   `json:"status_code"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	CNAME      []string `json:"cname"`
}

// Probe reports whether the record is a wildcard probe, not a result.
func (r Record) Probe() bool {
	return strings.HasPrefix(strings.ToLower(r.Host), ProbePrefix)
}

// Options are the dnsx settings Raijin passes through.
type Options struct {
	Binary    string
	Rate      int
	Threads   int
	Resolvers string
	// Raw, if set, receives dnsx's JSONL output unchanged.
	Raw io.Writer
	// Stats, if set, counts the output lines and the ones without the fields Raijin reads.
	Stats *Stats
}

// Stats counts dnsx's output lines: Bad have no "host" and "status_code" (or are not JSON), and give no
// record.
type Stats struct {
	Lines, Bad int
}

// Fields are the fields every dnsx result must have.
const Fields = "host and status_code"

// Run resolves the names and returns every record, plus the last stderr lines if dnsx failed.
func Run(ctx context.Context, names []string, opt Options) ([]Record, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "dnsx"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-subs-names-*.txt")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(names, "\n")+"\n"); err != nil {
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
	records, parseErr := parse(r, opt.Stats)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return records, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return records, tail(stderr.String(), 3), fmt.Errorf("dnsx exited: %w", waitErr)
	}
	return records, "", nil
}

// Args builds the dnsx command line. -rcode with every status makes dnsx write a line for names that
// do not resolve too (NXDOMAIN, SERVFAIL...), and -omit-raw leaves the raw DNS messages out.
//
// There is no -cname on purpose. The A and AAAA answers already carry the CNAME chain, and dnsx writes
// it in "cname". With -cname, dnsx also sends a CNAME query, which a resolver answers NOERROR even when
// the chain ends at a name that does not exist, and that NOERROR replaces the NXDOMAIN of the A query:
// the one status that makes a CNAME dangling would be lost (dnsx v1.2.1).
func Args(listFile string, opt Options) []string {
	args := []string{"-l", listFile, "-a", "-aaaa", "-resp", "-json", "-silent", "-nc", "-duc", "-omit-raw",
		"-rcode", "noerror,formerr,servfail,nxdomain,notimp,refused"}
	if opt.Rate > 0 {
		args = append(args, "-rl", fmt.Sprint(opt.Rate))
	}
	if opt.Threads > 0 {
		args = append(args, "-t", fmt.Sprint(opt.Threads))
	}
	if opt.Resolvers != "" {
		args = append(args, "-r", opt.Resolvers)
	}
	return args
}

// Parse reads dnsx JSONL. Lines that are not JSON objects with a host and a status_code are skipped,
// so a file with both engines' output can be read by both parsers.
func Parse(r io.Reader) ([]Record, error) {
	return parse(r, nil)
}

func parse(r io.Reader, st *Stats) ([]Record, error) {
	if st == nil {
		st = &Stats{}
	}
	var records []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		st.Lines++
		var rec Record
		if line[0] != '{' || json.Unmarshal(line, &rec) != nil || rec.Host == "" || rec.StatusCode == "" {
			st.Bad++
			continue
		}
		records = append(records, rec)
	}
	return records, sc.Err()
}

// ProbeName is a random name under parent that should not exist: if it resolves, parent has wildcard DNS.
func ProbeName(parent string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return ProbePrefix + hex.EncodeToString(b) + "." + parent
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
