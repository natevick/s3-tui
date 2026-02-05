package download

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natevick/s3-tui/internal/aws"
	"github.com/natevick/s3-tui/internal/security"
)

// Status represents the state of a download
type Status int

const (
	StatusPending Status = iota
	StatusInProgress
	StatusCompleted
	StatusFailed
	StatusCancelled
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusInProgress:
		return "downloading"
	case StatusCompleted:
		return "completed"
	case StatusFailed:
		return "failed"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// FileProgress tracks progress for a single file
type FileProgress struct {
	Key             string
	LocalPath       string
	Size            int64
	Downloaded      int64
	Status          Status
	Error           error
	StartedAt       time.Time
	CompletedAt     time.Time
}

// Progress tracks overall download progress
type Progress struct {
	TotalFiles      int
	CompletedFiles  int
	FailedFiles     int
	TotalBytes      int64
	DownloadedBytes int64
	CurrentFile     string
	Files           map[string]*FileProgress
	StartedAt       time.Time
	Status          Status
}

// PercentComplete returns the overall percentage
func (p Progress) PercentComplete() float64 {
	if p.TotalBytes == 0 {
		return 0
	}
	return float64(p.DownloadedBytes) / float64(p.TotalBytes) * 100
}

// Manager orchestrates downloads
type Manager struct {
	client      *aws.Client
	workers     int
	progress    Progress
	progressMu  sync.RWMutex
	cancelFunc  context.CancelFunc
	onProgress  func(Progress)
	onComplete  func(Progress)
}

// NewManager creates a new download manager
func NewManager(client *aws.Client, workers int) *Manager {
	if workers <= 0 {
		workers = 5
	}
	return &Manager{
		client:  client,
		workers: workers,
		progress: Progress{
			Files: make(map[string]*FileProgress),
		},
	}
}

// SetProgressCallback sets the progress callback
func (m *Manager) SetProgressCallback(fn func(Progress)) {
	m.onProgress = fn
}

// SetCompleteCallback sets the completion callback
func (m *Manager) SetCompleteCallback(fn func(Progress)) {
	m.onComplete = fn
}

// GetProgress returns the current progress
func (m *Manager) GetProgress() Progress {
	m.progressMu.RLock()
	defer m.progressMu.RUnlock()
	return m.progress
}

// Cancel cancels the current download
func (m *Manager) Cancel() {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
}

// DownloadFile downloads a single file
func (m *Manager) DownloadFile(ctx context.Context, bucket, key, localPath string) error {
	ctx, m.cancelFunc = context.WithCancel(ctx)

	// Get file metadata
	obj, err := m.client.GetObjectMetadata(ctx, bucket, key)
	if err != nil {
		return err
	}

	m.progressMu.Lock()
	m.progress = Progress{
		TotalFiles:  1,
		TotalBytes:  obj.Size,
		CurrentFile: key,
		Files: map[string]*FileProgress{
			key: {
				Key:       key,
				LocalPath: localPath,
				Size:      obj.Size,
				Status:    StatusInProgress,
				StartedAt: time.Now(),
			},
		},
		StartedAt: time.Now(),
		Status:    StatusInProgress,
	}
	m.progressMu.Unlock()

	m.notifyProgress()

	err = m.client.DownloadFile(ctx, bucket, key, localPath, func(dp aws.DownloadProgress) {
		m.progressMu.Lock()
		m.progress.DownloadedBytes = dp.BytesDownloaded
		if fp, ok := m.progress.Files[key]; ok {
			fp.Downloaded = dp.BytesDownloaded
		}
		m.progressMu.Unlock()
		m.notifyProgress()
	})

	m.progressMu.Lock()
	if err != nil {
		if ctx.Err() != nil {
			m.progress.Status = StatusCancelled
			m.progress.Files[key].Status = StatusCancelled
		} else {
			m.progress.Status = StatusFailed
			m.progress.Files[key].Status = StatusFailed
			m.progress.Files[key].Error = err
			m.progress.FailedFiles = 1
		}
	} else {
		m.progress.Status = StatusCompleted
		m.progress.CompletedFiles = 1
		m.progress.Files[key].Status = StatusCompleted
		m.progress.Files[key].CompletedAt = time.Now()
	}
	m.progressMu.Unlock()

	m.notifyProgress()
	m.notifyComplete()

	return err
}

// DownloadPrefix downloads all files under a prefix
func (m *Manager) DownloadPrefix(ctx context.Context, bucket, prefix, localDir string) error {
	ctx, m.cancelFunc = context.WithCancel(ctx)

	// List all objects under the prefix
	objects, err := m.client.ListAllObjects(ctx, bucket, prefix)
	if err != nil {
		return fmt.Errorf("failed to list objects: %w", err)
	}

	if len(objects) == 0 {
		return fmt.Errorf("no files found under prefix: %s", prefix)
	}

	// Initialize progress
	var totalBytes int64
	files := make(map[string]*FileProgress)
	for _, obj := range objects {
		totalBytes += obj.Size
		// Calculate local path relative to prefix with path traversal protection
		relPath := strings.TrimPrefix(obj.Key, prefix)
		localPath, err := security.SafePath(localDir, relPath)
		if err != nil {
			return fmt.Errorf("unsafe path for key %s: %w", obj.Key, err)
		}
		files[obj.Key] = &FileProgress{
			Key:       obj.Key,
			LocalPath: localPath,
			Size:      obj.Size,
			Status:    StatusPending,
		}
	}

	m.progressMu.Lock()
	m.progress = Progress{
		TotalFiles: len(objects),
		TotalBytes: totalBytes,
		Files:      files,
		StartedAt:  time.Now(),
		Status:     StatusInProgress,
	}
	m.progressMu.Unlock()

	m.notifyProgress()

	// Download files using worker pool
	err = m.downloadWithWorkers(ctx, bucket, objects, prefix, localDir)

	m.progressMu.Lock()
	if err != nil && ctx.Err() != nil {
		m.progress.Status = StatusCancelled
	} else if m.progress.FailedFiles > 0 {
		m.progress.Status = StatusFailed
	} else {
		m.progress.Status = StatusCompleted
	}
	m.progressMu.Unlock()

	m.notifyProgress()
	m.notifyComplete()

	return err
}

// DownloadMultiple downloads multiple selected objects
func (m *Manager) DownloadMultiple(ctx context.Context, bucket string, objects []aws.S3Object, prefix, localDir string) error {
	ctx, m.cancelFunc = context.WithCancel(ctx)

	if len(objects) == 0 {
		return fmt.Errorf("no files to download")
	}

	// Initialize progress
	var totalBytes int64
	files := make(map[string]*FileProgress)

	// Expand any prefixes to get all files
	var allObjects []aws.S3Object
	for _, obj := range objects {
		if obj.IsPrefix {
			// List all objects under this prefix
			subObjects, err := m.client.ListAllObjects(ctx, bucket, obj.Key)
			if err != nil {
				return fmt.Errorf("failed to list objects under %s: %w", obj.Key, err)
			}
			allObjects = append(allObjects, subObjects...)
		} else {
			allObjects = append(allObjects, obj)
		}
	}

	for _, obj := range allObjects {
		totalBytes += obj.Size
		// Calculate local path relative to prefix with path traversal protection
		relPath := strings.TrimPrefix(obj.Key, prefix)
		localPath, err := security.SafePath(localDir, relPath)
		if err != nil {
			return fmt.Errorf("unsafe path for key %s: %w", obj.Key, err)
		}
		files[obj.Key] = &FileProgress{
			Key:       obj.Key,
			LocalPath: localPath,
			Size:      obj.Size,
			Status:    StatusPending,
		}
	}

	m.progressMu.Lock()
	m.progress = Progress{
		TotalFiles: len(allObjects),
		TotalBytes: totalBytes,
		Files:      files,
		StartedAt:  time.Now(),
		Status:     StatusInProgress,
	}
	m.progressMu.Unlock()

	m.notifyProgress()

	// Download files using worker pool
	err := m.downloadWithWorkers(ctx, bucket, allObjects, prefix, localDir)

	m.progressMu.Lock()
	if err != nil && ctx.Err() != nil {
		m.progress.Status = StatusCancelled
	} else if m.progress.FailedFiles > 0 {
		m.progress.Status = StatusFailed
	} else {
		m.progress.Status = StatusCompleted
	}
	m.progressMu.Unlock()

	m.notifyProgress()
	m.notifyComplete()

	return err
}

// downloadWithWorkers downloads files using a worker pool
func (m *Manager) downloadWithWorkers(ctx context.Context, bucket string, objects []aws.S3Object, prefix, localDir string) error {
	jobs := make(chan aws.S3Object, len(objects))
	var wg sync.WaitGroup
	var downloadedBytes int64
	var completedFiles int32
	var failedFiles int32

	// Start workers
	for i := 0; i < m.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Get the pre-validated local path from FileProgress
				m.progressMu.Lock()
				m.progress.CurrentFile = obj.Key
				var localPath string
				if fp, ok := m.progress.Files[obj.Key]; ok {
					localPath = fp.LocalPath
					fp.Status = StatusInProgress
					fp.StartedAt = time.Now()
				}
				m.progressMu.Unlock()

				if localPath == "" {
					// Fallback with validation if not in progress map
					relPath := strings.TrimPrefix(obj.Key, prefix)
					var err error
					localPath, err = security.SafePath(localDir, relPath)
					if err != nil {
						atomic.AddInt32(&failedFiles, 1)
						m.progressMu.Lock()
						if fp, ok := m.progress.Files[obj.Key]; ok {
							fp.Status = StatusFailed
							fp.Error = err
						}
						m.progress.FailedFiles = int(atomic.LoadInt32(&failedFiles))
						m.progressMu.Unlock()
						continue
					}
				}

				m.notifyProgress()

				err := m.client.DownloadFile(ctx, bucket, obj.Key, localPath, func(dp aws.DownloadProgress) {
					m.progressMu.Lock()
					if fp, ok := m.progress.Files[obj.Key]; ok {
						fp.Downloaded = dp.BytesDownloaded
					}
					// Update total downloaded
					var total int64
					for _, fp := range m.progress.Files {
						total += fp.Downloaded
					}
					m.progress.DownloadedBytes = total
					m.progressMu.Unlock()
					m.notifyProgress()
				})

				m.progressMu.Lock()
				if err != nil {
					atomic.AddInt32(&failedFiles, 1)
					if fp, ok := m.progress.Files[obj.Key]; ok {
						if ctx.Err() != nil {
							fp.Status = StatusCancelled
						} else {
							fp.Status = StatusFailed
							fp.Error = err
						}
					}
					m.progress.FailedFiles = int(atomic.LoadInt32(&failedFiles))
				} else {
					atomic.AddInt64(&downloadedBytes, obj.Size)
					atomic.AddInt32(&completedFiles, 1)
					if fp, ok := m.progress.Files[obj.Key]; ok {
						fp.Status = StatusCompleted
						fp.Downloaded = obj.Size
						fp.CompletedAt = time.Now()
					}
					m.progress.CompletedFiles = int(atomic.LoadInt32(&completedFiles))
				}
				m.progressMu.Unlock()
				m.notifyProgress()
			}
		}()
	}

	// Send jobs
	for _, obj := range objects {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		case jobs <- obj:
		}
	}
	close(jobs)

	wg.Wait()
	return nil
}

func (m *Manager) notifyProgress() {
	if m.onProgress != nil {
		m.progressMu.RLock()
		p := m.progress
		m.progressMu.RUnlock()
		m.onProgress(p)
	}
}

func (m *Manager) notifyComplete() {
	if m.onComplete != nil {
		m.progressMu.RLock()
		p := m.progress
		m.progressMu.RUnlock()
		m.onComplete(p)
	}
}
