package aws

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Bucket represents an S3 bucket
type Bucket struct {
	Name         string
	CreationDate time.Time
	Region       string
}

// S3Object represents an object or prefix in S3
type S3Object struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
	IsPrefix     bool // true if this is a "folder" (common prefix)
}

// DisplayName returns the object's display name (last part of key)
func (o S3Object) DisplayName() string {
	key := strings.TrimSuffix(o.Key, "/")
	parts := strings.Split(key, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if o.IsPrefix {
			return name + "/"
		}
		return name
	}
	return o.Key
}

// ListBuckets returns all S3 buckets accessible to the current credentials
func (c *Client) ListBuckets(ctx context.Context) ([]Bucket, error) {
	output, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	buckets := make([]Bucket, len(output.Buckets))
	for i, b := range output.Buckets {
		buckets[i] = Bucket{
			Name:         aws.ToString(b.Name),
			CreationDate: aws.ToTime(b.CreationDate),
		}
	}

	return buckets, nil
}

// GetBucketRegion returns the region for a bucket
func (c *Client) GetBucketRegion(ctx context.Context, bucket string) (string, error) {
	output, err := c.S3.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get bucket location: %w", err)
	}

	region := string(output.LocationConstraint)
	if region == "" {
		region = "us-east-1" // Default region for buckets without explicit location
	}

	return region, nil
}

// ListObjects lists objects and common prefixes at the given prefix
func (c *Client) ListObjects(ctx context.Context, bucket, prefix string) ([]S3Object, error) {
	var objects []S3Object

	// Use delimiter to get "folder-like" behavior
	delimiter := "/"

	paginator := s3.NewListObjectsV2Paginator(c.S3, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String(delimiter),
	})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		// Add common prefixes (folders)
		for _, cp := range output.CommonPrefixes {
			objects = append(objects, S3Object{
				Key:      aws.ToString(cp.Prefix),
				IsPrefix: true,
			})
		}

		// Add objects (files)
		for _, obj := range output.Contents {
			key := aws.ToString(obj.Key)
			// Skip the prefix itself if it appears as an object
			if key == prefix {
				continue
			}
			objects = append(objects, S3Object{
				Key:          key,
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
				ETag:         strings.Trim(aws.ToString(obj.ETag), "\""),
				IsPrefix:     false,
			})
		}
	}

	return objects, nil
}

// ListAllObjects lists all objects recursively under a prefix (no delimiter)
func (c *Client) ListAllObjects(ctx context.Context, bucket, prefix string) ([]S3Object, error) {
	var objects []S3Object

	paginator := s3.NewListObjectsV2Paginator(c.S3, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range output.Contents {
			key := aws.ToString(obj.Key)
			// Skip if it ends with / (folder marker)
			if strings.HasSuffix(key, "/") {
				continue
			}
			objects = append(objects, S3Object{
				Key:          key,
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
				ETag:         strings.Trim(aws.ToString(obj.ETag), "\""),
				IsPrefix:     false,
			})
		}
	}

	return objects, nil
}

// GetObjectMetadata retrieves metadata for a single object
func (c *Client) GetObjectMetadata(ctx context.Context, bucket, key string) (*S3Object, error) {
	output, err := c.S3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object metadata: %w", err)
	}

	return &S3Object{
		Key:          key,
		Size:         aws.ToInt64(output.ContentLength),
		LastModified: aws.ToTime(output.LastModified),
		ETag:         strings.Trim(aws.ToString(output.ETag), "\""),
		IsPrefix:     false,
	}, nil
}

// DownloadProgress tracks download progress
type DownloadProgress struct {
	BytesDownloaded int64
	TotalBytes      int64
	Key             string
}

// ProgressWriter wraps an io.WriterAt to track download progress
type ProgressWriter struct {
	writer     io.WriterAt
	downloaded int64
	total      int64
	key        string
	onProgress func(DownloadProgress)
}

func (pw *ProgressWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := pw.writer.WriteAt(p, off)
	if err == nil {
		pw.downloaded += int64(n)
		if pw.onProgress != nil {
			pw.onProgress(DownloadProgress{
				BytesDownloaded: pw.downloaded,
				TotalBytes:      pw.total,
				Key:             pw.key,
			})
		}
	}
	return n, err
}

// DownloadFile downloads a single file from S3 to the local filesystem
func (c *Client) DownloadFile(ctx context.Context, bucket, key, localPath string, onProgress func(DownloadProgress)) error {
	// Ensure directory exists with secure permissions
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Get file size first
	obj, err := c.GetObjectMetadata(ctx, bucket, key)
	if err != nil {
		return err
	}

	// Create local file with secure permissions (owner read/write only)
	file, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Create download manager
	downloader := manager.NewDownloader(c.S3, func(d *manager.Downloader) {
		d.PartSize = 10 * 1024 * 1024 // 10MB parts
		d.Concurrency = 5
	})

	// Wrap writer for progress tracking
	pw := &ProgressWriter{
		writer:     file,
		total:      obj.Size,
		key:        key,
		onProgress: onProgress,
	}

	_, err = downloader.Download(ctx, pw, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		os.Remove(localPath) // Clean up on failure
		return fmt.Errorf("failed to download file: %w", err)
	}

	return nil
}

// GetObject retrieves an object's content
func (c *Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	output, err := c.S3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	return output.Body, nil
}

// CheckBucketAccess verifies if we have access to a bucket
func (c *Client) CheckBucketAccess(ctx context.Context, bucket string) error {
	_, err := c.S3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return fmt.Errorf("no access to bucket %s: %w", bucket, err)
	}
	return nil
}

// GetStorageClass returns the storage class for display
func GetStorageClass(class types.StorageClass) string {
	if class == "" {
		return "STANDARD"
	}
	return string(class)
}
