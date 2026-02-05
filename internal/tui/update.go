package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/natevick/s3-tui/internal/aws"
	"github.com/natevick/s3-tui/internal/download"
	"github.com/natevick/s3-tui/internal/security"
	"github.com/natevick/s3-tui/internal/views/bookmarksview"
	"github.com/natevick/s3-tui/internal/views/browser"
	"github.com/natevick/s3-tui/internal/views/buckets"
	"github.com/natevick/s3-tui/internal/views/profiles"
)

// Update handles all messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		// Handle prompt input first
		if m.showPrompt {
			return m.handlePromptKey(msg)
		}

		// Global key handling
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.cancel()
			return m, tea.Quit

		case key.Matches(msg, m.keys.Help):
			m.showHelp = !m.showHelp
			return m, nil

		case key.Matches(msg, m.keys.Tab), key.Matches(msg, m.keys.Right):
			m.nextView()
			return m, nil

		case key.Matches(msg, m.keys.ShiftTab), key.Matches(msg, m.keys.Left):
			m.prevView()
			return m, nil

		case key.Matches(msg, m.keys.Buckets):
			m.activeView = ViewBuckets
			return m, nil

		case key.Matches(msg, m.keys.Browser):
			m.activeView = ViewBrowser
			return m, nil

		case key.Matches(msg, m.keys.Bookmarks):
			m.activeView = ViewBookmarks
			return m, nil

		case key.Matches(msg, m.keys.Cancel):
			if m.activeView == ViewDownload && m.downloadView.IsActive() {
				if m.downloadMgr != nil {
					m.downloadMgr.Cancel()
				}
				return m, nil
			}
			// Close help if open
			if m.showHelp {
				m.showHelp = false
				return m, nil
			}

		case key.Matches(msg, m.keys.Refresh):
			return m.handleRefresh()
		}

	case demoReadyMsg:
		// Load mock data for demo mode
		return m, m.loadDemoBuckets()

	case profilesReadyMsg:
		// Load available profiles
		if err := m.profilesView.LoadProfiles(); err != nil {
			m.errorMsg = security.SanitizeErrorGeneric(err, "Failed to load profiles")
			m.errorTimeout = time.Now().Add(5 * time.Second)
		}
		return m, nil

	case profiles.SelectedMsg:
		// Profile was selected, initialize AWS with it
		m.profile = msg.Profile
		m.activeView = ViewBuckets
		m.bucketsView.SetLoading(true)
		return m, m.initAWS()

	case awsClientReadyMsg:
		m.client = msg.client
		m.downloadMgr = download.NewManager(m.client, 5)

		// If a bucket was specified on command line, go directly to it
		if m.initialBucket != "" {
			m.currentBucket = m.initialBucket
			m.browserView.SetBucket(m.initialBucket)
			m.browserView.SetLoading(true)
			return m, tea.Batch(m.loadBuckets(), m.loadObjects())
		}
		return m, m.loadBuckets()

	case bookmarkStoreReadyMsg:
		m.bookmarkStore = msg.store
		m.bookmarksView.SetStore(m.bookmarkStore)
		return m, nil

	case BucketsLoadedMsg:
		if msg.Err != nil {
			m.bucketsView.SetError(msg.Err)
			m.errorMsg = security.SanitizeErrorGeneric(msg.Err, "Loading buckets")
			m.errorTimeout = time.Now().Add(5 * time.Second)
		} else {
			m.bucketsView.SetBuckets(msg.Buckets)
		}
		return m, nil

	case ObjectsLoadedMsg:
		if msg.Err != nil {
			m.browserView.SetError(msg.Err)
			m.errorMsg = security.SanitizeErrorGeneric(msg.Err, "Loading objects")
			m.errorTimeout = time.Now().Add(5 * time.Second)
		} else {
			m.browserView.SetObjects(msg.Objects)
		}
		return m, nil

	case DownloadProgressMsg:
		m.downloadView.SetProgress(msg.Progress)
		return m, nil

	case downloadStartedMsg:
		// Start listening for progress updates
		return m, m.listenForProgress(msg.progressChan)

	case downloadProgressTickMsg:
		m.downloadView.SetProgress(msg.progress)
		if msg.done {
			if msg.progress.Status == download.StatusCompleted {
				m.statusMsg = fmt.Sprintf("Downloaded %d files", msg.progress.CompletedFiles)
			} else if msg.progress.Status == download.StatusFailed {
				m.errorMsg = "Download failed"
				m.errorTimeout = time.Now().Add(5 * time.Second)
			}
			return m, nil
		}
		return m, m.listenForProgress(msg.progressChan)

	case ErrorMsg:
		if msg.Err != nil {
			m.errorMsg = security.SanitizeError(msg.Err)
			m.errorTimeout = time.Now().Add(5 * time.Second)
		}
		return m, nil

	case TickMsg:
		// Clear error after timeout
		if m.errorMsg != "" && time.Now().After(m.errorTimeout) {
			m.errorMsg = ""
		}
		return m, tickCmd()
	}

	// Route to active view
	switch m.activeView {
	case ViewProfiles:
		var cmd tea.Cmd
		m.profilesView, cmd = m.profilesView.Update(msg)
		cmds = append(cmds, cmd)

	case ViewBuckets:
		var cmd tea.Cmd
		m.bucketsView, cmd = m.bucketsView.Update(msg)
		cmds = append(cmds, cmd)

		// Check for actions
		action, bucket := m.bucketsView.ConsumeAction()
		switch action {
		case buckets.ActionSelect:
			m.currentBucket = bucket
			m.currentPrefix = ""
			m.browserView.SetBucket(bucket)
			m.browserView.SetLoading(true)
			m.activeView = ViewBrowser
			cmds = append(cmds, m.loadObjects())

		case buckets.ActionBookmark:
			m.showBucketBookmarkPrompt(bucket)
		}

	case ViewBrowser:
		var cmd tea.Cmd
		m.browserView, cmd = m.browserView.Update(msg)
		cmds = append(cmds, cmd)

		// Check for actions
		action, obj, objs := m.browserView.ConsumeAction()
		switch action {
		case browser.ActionNavigate, browser.ActionBack:
			m.currentPrefix = m.browserView.Prefix()
			m.browserView.SetLoading(true)
			cmds = append(cmds, m.loadObjects())

		case browser.ActionDownload:
			if len(objs) > 0 {
				m.showMultiDownloadPrompt(objs)
			} else {
				m.showDownloadPrompt(obj)
			}

		case browser.ActionSync:
			m.showSyncPrompt()

		case browser.ActionBookmark:
			m.showBookmarkPrompt()
		}

	case ViewDownload:
		var cmd tea.Cmd
		m.downloadView, cmd = m.downloadView.Update(msg)
		cmds = append(cmds, cmd)

	case ViewBookmarks:
		var cmd tea.Cmd
		m.bookmarksView, cmd = m.bookmarksView.Update(msg)
		cmds = append(cmds, cmd)

		// Check for actions
		action, id := m.bookmarksView.ConsumeAction()
		switch action {
		case bookmarksview.ActionSelect:
			if bookmark, ok := m.bookmarkStore.Get(id); ok {
				m.currentBucket = bookmark.Bucket
				m.currentPrefix = bookmark.Prefix
				m.browserView.SetBucket(bookmark.Bucket)
				m.browserView.SetPrefix(bookmark.Prefix)
				m.browserView.SetLoading(true)
				m.activeView = ViewBrowser
				cmds = append(cmds, m.loadObjects())
			}

		case bookmarksview.ActionDelete:
			if m.bookmarkStore != nil {
				if err := m.bookmarkStore.Remove(id); err != nil {
					m.errorMsg = security.SanitizeErrorGeneric(err, "Removing bookmark")
					m.errorTimeout = time.Now().Add(5 * time.Second)
				} else {
					m.bookmarksView.Refresh()
					m.statusMsg = "Bookmark removed"
				}
			}
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) nextView() {
	switch m.activeView {
	case ViewBuckets:
		m.activeView = ViewBrowser
	case ViewBrowser:
		m.activeView = ViewBookmarks
	case ViewBookmarks:
		m.activeView = ViewBuckets
	case ViewDownload:
		m.activeView = ViewBuckets
	}
}

func (m *Model) prevView() {
	switch m.activeView {
	case ViewBuckets:
		m.activeView = ViewBookmarks
	case ViewBrowser:
		m.activeView = ViewBuckets
	case ViewBookmarks:
		m.activeView = ViewBrowser
	case ViewDownload:
		m.activeView = ViewBuckets
	}
}

func (m Model) handleRefresh() (tea.Model, tea.Cmd) {
	switch m.activeView {
	case ViewBuckets:
		m.bucketsView.SetLoading(true)
		return m, m.loadBuckets()
	case ViewBrowser:
		m.browserView.SetLoading(true)
		return m, m.loadObjects()
	case ViewBookmarks:
		m.bookmarksView.Refresh()
	}
	return m, nil
}

// Prompt handling

func (m *Model) showDownloadPrompt(obj aws.S3Object) {
	m.showPrompt = true
	m.promptType = "download"
	m.promptDefault = m.browserView.DefaultDownloadPath(obj)
	m.promptInput = m.promptDefault
	m.promptCursor = len(m.promptInput)

	if obj.IsPrefix {
		m.promptText = fmt.Sprintf("Download all files in '%s' to:", obj.DisplayName())
	} else {
		m.promptText = fmt.Sprintf("Download '%s' to:", obj.DisplayName())
	}
}

func (m *Model) showMultiDownloadPrompt(objs []aws.S3Object) {
	m.showPrompt = true
	m.promptType = "multi-download"
	m.promptDefault = "./download"
	m.promptInput = m.promptDefault
	m.promptCursor = len(m.promptInput)
	m.promptText = fmt.Sprintf("Download %d selected items to:", len(objs))
	m.pendingDownloadObjects = objs
}

func (m *Model) showSyncPrompt() {
	m.showPrompt = true
	m.promptType = "sync"

	// Default to current prefix folder name
	defaultPath := "./"
	if m.currentPrefix != "" {
		parts := strings.Split(strings.TrimSuffix(m.currentPrefix, "/"), "/")
		if len(parts) > 0 {
			defaultPath = "./" + parts[len(parts)-1]
		}
	}

	m.promptDefault = defaultPath
	m.promptInput = m.promptDefault
	m.promptCursor = len(m.promptInput)
	m.promptText = fmt.Sprintf("Sync '%s' to local directory:", m.currentPrefix)
}

func (m *Model) showBookmarkPrompt() {
	m.showPrompt = true
	m.promptType = "bookmark"

	// Default name based on prefix
	defaultName := m.currentBucket
	if m.currentPrefix != "" {
		parts := strings.Split(strings.TrimSuffix(m.currentPrefix, "/"), "/")
		if len(parts) > 0 {
			defaultName = parts[len(parts)-1]
		}
	}

	m.promptDefault = defaultName
	m.promptInput = m.promptDefault
	m.promptCursor = len(m.promptInput)
	m.promptText = "Bookmark name:"
}

func (m *Model) showBucketBookmarkPrompt(bucket string) {
	m.showPrompt = true
	m.promptType = "bucket-bookmark"
	m.promptDefault = bucket
	m.promptInput = m.promptDefault
	m.promptCursor = len(m.promptInput)
	m.promptText = fmt.Sprintf("Bookmark bucket '%s' as:", bucket)
	m.pendingBookmarkBucket = bucket
}

func (m Model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.showPrompt = false
		m.promptInput = ""
		return m, nil

	case tea.KeyEnter:
		return m.executePromptAction()

	case tea.KeyBackspace:
		if len(m.promptInput) > 0 && m.promptCursor > 0 {
			m.promptInput = m.promptInput[:m.promptCursor-1] + m.promptInput[m.promptCursor:]
			m.promptCursor--
		}
		return m, nil

	case tea.KeyDelete:
		if m.promptCursor < len(m.promptInput) {
			m.promptInput = m.promptInput[:m.promptCursor] + m.promptInput[m.promptCursor+1:]
		}
		return m, nil

	case tea.KeyLeft:
		if m.promptCursor > 0 {
			m.promptCursor--
		}
		return m, nil

	case tea.KeyRight:
		if m.promptCursor < len(m.promptInput) {
			m.promptCursor++
		}
		return m, nil

	case tea.KeyHome, tea.KeyCtrlA:
		m.promptCursor = 0
		return m, nil

	case tea.KeyEnd, tea.KeyCtrlE:
		m.promptCursor = len(m.promptInput)
		return m, nil

	case tea.KeyRunes:
		// Insert characters
		m.promptInput = m.promptInput[:m.promptCursor] + string(msg.Runes) + m.promptInput[m.promptCursor:]
		m.promptCursor += len(msg.Runes)
		return m, nil
	}

	return m, nil
}

func (m Model) executePromptAction() (tea.Model, tea.Cmd) {
	m.showPrompt = false
	input := m.promptInput
	m.promptInput = ""

	if input == "" {
		return m, nil
	}

	switch m.promptType {
	case "download":
		obj, _ := m.browserView.SelectedObject()
		localPath := input

		// Make path absolute if relative
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Clean(localPath)
		}

		m.activeView = ViewDownload
		m.browserView.ClearSelection()
		return m, m.startDownload(obj.Key, localPath, obj.IsPrefix)

	case "multi-download":
		localPath := input
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Clean(localPath)
		}

		objs := m.pendingDownloadObjects
		m.pendingDownloadObjects = nil
		m.activeView = ViewDownload
		m.browserView.ClearSelection()
		return m, m.startMultiDownload(objs, localPath)

	case "sync":
		localPath := input
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Clean(localPath)
		}

		m.activeView = ViewDownload

		// Create sync manager and sync
		return m, func() tea.Msg {
			syncMgr := download.NewSyncManager(m.client)

			// Set up progress callback
			progressChan := make(chan download.Progress, 10)
			m.downloadMgr.SetProgressCallback(func(p download.Progress) {
				select {
				case progressChan <- p:
				default:
				}
			})

			go func() {
				err := syncMgr.Sync(m.ctx, m.currentBucket, m.currentPrefix, localPath, m.downloadMgr)
				if err != nil {
					progressChan <- download.Progress{Status: download.StatusFailed}
				}
				close(progressChan)
			}()

			return downloadStartedMsg{progressChan: progressChan}
		}

	case "bookmark":
		if m.bookmarkStore != nil {
			_, err := m.bookmarkStore.Add(input, m.currentBucket, m.currentPrefix)
			if err != nil {
				m.errorMsg = security.SanitizeErrorGeneric(err, "Adding bookmark")
				m.errorTimeout = time.Now().Add(5 * time.Second)
			} else {
				m.statusMsg = "Bookmark added"
				m.bookmarksView.Refresh()
			}
		}

	case "bucket-bookmark":
		if m.bookmarkStore != nil && m.pendingBookmarkBucket != "" {
			_, err := m.bookmarkStore.Add(input, m.pendingBookmarkBucket, "")
			if err != nil {
				m.errorMsg = security.SanitizeErrorGeneric(err, "Adding bookmark")
				m.errorTimeout = time.Now().Add(5 * time.Second)
			} else {
				m.statusMsg = "Bookmark added"
				m.bookmarksView.Refresh()
			}
		}
		m.pendingBookmarkBucket = ""
	}

	return m, nil
}

// downloadProgressTickMsg is sent for progress updates
type downloadProgressTickMsg struct {
	progress     download.Progress
	progressChan <-chan download.Progress
	done         bool
}

// listenForProgress returns a command that listens for progress updates
func (m Model) listenForProgress(ch <-chan download.Progress) tea.Cmd {
	return func() tea.Msg {
		progress, ok := <-ch
		return downloadProgressTickMsg{
			progress:     progress,
			progressChan: ch,
			done:         !ok,
		}
	}
}
