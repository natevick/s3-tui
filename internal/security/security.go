package security

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Input validation constants
const (
	MaxBookmarkNameLen = 255
	MaxProfileNameLen  = 128
	MaxBucketNameLen   = 63
	MaxPathLen         = 4096
)

// ValidBookmarkName validates a bookmark name
func ValidBookmarkName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("bookmark name cannot be empty")
	}
	if len(name) > MaxBookmarkNameLen {
		return fmt.Errorf("bookmark name too long (max %d characters)", MaxBookmarkNameLen)
	}
	// Allow alphanumeric, spaces, hyphens, underscores, dots, slashes
	if !regexp.MustCompile(`^[\w\-\s\./]+$`).MatchString(name) {
		return fmt.Errorf("bookmark name contains invalid characters")
	}
	return nil
}

// ValidProfileName validates an AWS profile name
func ValidProfileName(name string) error {
	if name == "" {
		return nil // Empty is allowed (uses default)
	}
	if len(name) > MaxProfileNameLen {
		return fmt.Errorf("profile name too long (max %d characters)", MaxProfileNameLen)
	}
	// AWS profile names: alphanumeric, hyphens, underscores
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name) {
		return fmt.Errorf("profile name contains invalid characters")
	}
	return nil
}

// ValidBucketName validates an S3 bucket name
func ValidBucketName(name string) error {
	if name == "" {
		return nil // Empty is allowed
	}
	if len(name) < 3 || len(name) > MaxBucketNameLen {
		return fmt.Errorf("bucket name must be 3-%d characters", MaxBucketNameLen)
	}
	// S3 bucket naming rules (simplified)
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`).MatchString(name) {
		return fmt.Errorf("invalid bucket name format")
	}
	return nil
}

// SafePath validates that a path stays within the base directory
// Returns the cleaned absolute path or an error if path traversal is detected
func SafePath(baseDir, relativePath string) (string, error) {
	// Clean and resolve the base directory
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %w", err)
	}

	// Join and clean the full path
	fullPath := filepath.Join(absBase, relativePath)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Ensure the path is within the base directory
	// Add trailing separator to prevent partial matches (e.g., /tmp/foo matching /tmp/foobar)
	if !strings.HasPrefix(absPath+string(filepath.Separator), absBase+string(filepath.Separator)) &&
		absPath != absBase {
		return "", fmt.Errorf("path traversal detected: path escapes base directory")
	}

	// Check for dangerous paths
	dangerousPaths := []string{"/dev/", "/proc/", "/sys/", "/etc/"}
	for _, dangerous := range dangerousPaths {
		if strings.Contains(absPath, dangerous) {
			return "", fmt.Errorf("invalid path: cannot write to system directories")
		}
	}

	if len(absPath) > MaxPathLen {
		return "", fmt.Errorf("path too long (max %d characters)", MaxPathLen)
	}

	return absPath, nil
}

// SanitizeError removes sensitive information from error messages
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	// Remove potential AWS account IDs (12 digits)
	msg = regexp.MustCompile(`\b\d{12}\b`).ReplaceAllString(msg, "[account-id]")

	// Remove potential ARNs
	msg = regexp.MustCompile(`arn:aws:[^:\s]+:[^:\s]*:[^:\s]*:[^\s]+`).ReplaceAllString(msg, "[arn]")

	// Remove S3 bucket names in common error patterns
	msg = regexp.MustCompile(`bucket[:\s]+['"]?([a-z0-9.-]+)['"]?`).ReplaceAllString(msg, "bucket: [bucket]")

	// Remove access key IDs
	msg = regexp.MustCompile(`AKIA[A-Z0-9]{16}`).ReplaceAllString(msg, "[access-key]")

	// Remove full file paths that might be sensitive
	msg = regexp.MustCompile(`/Users/[^/\s]+`).ReplaceAllString(msg, "/Users/[user]")
	msg = regexp.MustCompile(`/home/[^/\s]+`).ReplaceAllString(msg, "/home/[user]")

	return msg
}

// SanitizeErrorGeneric provides a user-friendly error without details
func SanitizeErrorGeneric(err error, context string) string {
	if err == nil {
		return ""
	}

	// Check for common AWS error types and provide friendly messages
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "access denied") || strings.Contains(errStr, "accessdenied"):
		return fmt.Sprintf("%s: access denied - check your permissions", context)
	case strings.Contains(errStr, "no such bucket") || strings.Contains(errStr, "nosuchbucket"):
		return fmt.Sprintf("%s: bucket not found", context)
	case strings.Contains(errStr, "no such key") || strings.Contains(errStr, "nosuchkey"):
		return fmt.Sprintf("%s: object not found", context)
	case strings.Contains(errStr, "expired") || strings.Contains(errStr, "token"):
		return fmt.Sprintf("%s: credentials expired - run 'aws sso login'", context)
	case strings.Contains(errStr, "credential"):
		return fmt.Sprintf("%s: credential error - check your AWS configuration", context)
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return fmt.Sprintf("%s: request timed out", context)
	case strings.Contains(errStr, "connection"):
		return fmt.Sprintf("%s: connection error - check your network", context)
	default:
		return fmt.Sprintf("%s: %s", context, SanitizeError(err))
	}
}
