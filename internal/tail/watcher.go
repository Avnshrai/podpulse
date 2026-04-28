// Directory watcher: scans /var/log/pods periodically, finds container
// log files, and starts a FileTailer per file. New files (new pods) are
// picked up on the next scan; files whose tailers exit are forgotten so
// they can be restarted if they reappear.
package tail

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PodPath is the metadata extracted from a CRI log file path:
//
//	/var/log/pods/<ns>_<pod>_<uid>/<container>/<index>.log
type PodPath struct {
	Namespace string
	Pod       string
	UID       string
	Container string
	Path      string
}

// ParsePodPath decodes a CRI log file path. Returns ok=false if the
// path doesn't look like a kubelet pod log.
func ParsePodPath(path string) (PodPath, bool) {
	// Expect: <root>/<ns>_<pod>_<uid>/<container>/<index>.log
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	if len(parts) < 4 {
		return PodPath{}, false
	}
	file := parts[len(parts)-1]
	container := parts[len(parts)-2]
	dir := parts[len(parts)-3]

	if !strings.HasSuffix(file, ".log") {
		return PodPath{}, false
	}

	// dir is "<ns>_<pod>_<uid>". Pod names contain hyphens but not
	// underscores, so the first underscore is ns/pod and the last is
	// pod/uid.
	first := strings.IndexByte(dir, '_')
	last := strings.LastIndexByte(dir, '_')
	if first < 0 || last <= first {
		return PodPath{}, false
	}

	return PodPath{
		Namespace: dir[:first],
		Pod:       dir[first+1 : last],
		UID:       dir[last+1:],
		Container: container,
		Path:      path,
	}, true
}

// Watcher scans the pod-log root and runs a FileTailer per file.
type Watcher struct {
	Root       string
	ScanEvery  time.Duration
	Logger     *slog.Logger
	OnRecord   func(PodPath, Record) // called for every parsed line
	OnNewPath  func(PodPath)         // optional: called once per discovered file

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// Run blocks until ctx is cancelled. Picks up new files on every scan.
func (w *Watcher) Run(ctx context.Context) error {
	if w.Root == "" {
		w.Root = "/var/log/pods"
	}
	if w.ScanEvery == 0 {
		w.ScanEvery = 5 * time.Second
	}
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	w.running = map[string]context.CancelFunc{}

	w.scan(ctx)
	tick := time.NewTicker(w.ScanEvery)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			w.scan(ctx)
		}
	}
}

func (w *Watcher) scan(ctx context.Context) {
	matches, err := filepath.Glob(filepath.Join(w.Root, "*", "*", "*.log"))
	if err != nil {
		w.Logger.Warn("scan failed", "root", w.Root, "err", err)
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range matches {
		if _, ok := w.running[p]; ok {
			continue
		}
		pp, ok := ParsePodPath(p)
		if !ok {
			continue
		}
		// Skip our own pods to avoid feedback loops.
		if strings.HasPrefix(pp.Pod, "podpulse-") {
			continue
		}
		if w.OnNewPath != nil {
			w.OnNewPath(pp)
		}
		fctx, cancel := context.WithCancel(ctx)
		w.running[p] = cancel
		path := p
		meta := pp
		go func() {
			defer func() {
				w.mu.Lock()
				delete(w.running, path)
				w.mu.Unlock()
			}()
			tt := &FileTailer{
				Path:   path,
				Origin: FromEnd,
				Logger: w.Logger,
				Emit: func(r Record) {
					if w.OnRecord != nil {
						w.OnRecord(meta, r)
					}
				},
			}
			if err := tt.Run(fctx); err != nil && fctx.Err() == nil {
				w.Logger.Debug("tailer exit", "path", path, "err", err)
			}
		}()
	}
}
