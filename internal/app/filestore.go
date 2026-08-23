package app

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errEmptyUpload    = errors.New("uploaded file is empty")
	errUploadTooLarge = errors.New("uploaded file is too large")
)

type FileStorage struct {
	root string
}

type stagedFile struct {
	tempPath     string
	storageKey   string
	md5          string
	sha256       string
	size         int64
	contentType  string
	originalName string
}

func NewFileStorage(root string) (*FileStorage, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("files directory is empty")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(absRoot, ".tmp"), 0o750); err != nil {
		return nil, err
	}
	staleUploads, _ := filepath.Glob(filepath.Join(absRoot, ".tmp", "upload-*"))
	for _, staleUpload := range staleUploads {
		_ = os.Remove(staleUpload)
	}
	return &FileStorage{root: absRoot}, nil
}

func (s *FileStorage) Stage(reader io.Reader, filename string, maxBytes int64) (stagedFile, error) {
	temp, err := os.CreateTemp(filepath.Join(s.root, ".tmp"), "upload-*")
	if err != nil {
		return stagedFile{}, err
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, md5Hash, sha256Hash), io.LimitReader(reader, maxBytes+1))
	if err != nil {
		cleanup()
		return stagedFile{}, err
	}
	if written == 0 {
		cleanup()
		return stagedFile{}, errEmptyUpload
	}
	if written > maxBytes {
		cleanup()
		return stagedFile{}, errUploadTooLarge
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return stagedFile{}, err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return stagedFile{}, err
	}

	sha256Digest := hex.EncodeToString(sha256Hash.Sum(nil))
	cleanName := sanitizeFilename(filename)
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(cleanName)))
	if contentType == "" {
		contentType = sniffContentType(tempPath)
	}
	return stagedFile{
		tempPath: tempPath, storageKey: filepath.Join(sha256Digest[:2], sha256Digest),
		md5: hex.EncodeToString(md5Hash.Sum(nil)), sha256: sha256Digest, size: written,
		contentType: contentType, originalName: cleanName,
	}, nil
}

func (s *FileStorage) Commit(staged stagedFile) error {
	destination, err := s.path(staged.storageKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		return os.Remove(staged.tempPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(staged.tempPath, destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o640); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func (s *FileStorage) Discard(staged stagedFile) { _ = os.Remove(staged.tempPath) }

func (s *FileStorage) Open(storageKey string) (*os.File, error) {
	path, err := s.path(storageKey)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (s *FileStorage) Remove(storageKey string) error {
	path, err := s.path(storageKey)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func (s *FileStorage) path(storageKey string) (string, error) {
	if storageKey == "" || filepath.IsAbs(storageKey) {
		return "", errors.New("invalid storage key")
	}
	clean := filepath.Clean(storageKey)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid storage key")
	}
	path := filepath.Join(s.root, clean)
	relative, err := filepath.Rel(s.root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid storage key")
	}
	return path, nil
}

func sanitizeFilename(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = filepath.Base(value)
	value = strings.TrimSpace(strings.ToValidUTF8(value, "_"))
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			builder.WriteRune('_')
		} else {
			builder.WriteRune(r)
		}
	}
	value = strings.TrimSpace(builder.String())
	if value == "" || value == "." {
		value = "download"
	}
	if utf8.RuneCountInString(value) > 200 {
		runes := []rune(value)
		value = string(runes[:200])
	}
	return value
}

func sniffContentType(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "application/octet-stream"
	}
	defer file.Close()
	buffer := make([]byte, 512)
	read, _ := file.Read(buffer)
	if read == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(buffer[:read])
}

func uploadErrorMessage(err error, maxBytes int64) string {
	switch {
	case errors.Is(err, errEmptyUpload):
		return "不能上传空文件"
	case errors.Is(err, errUploadTooLarge):
		return fmt.Sprintf("文件不能超过 %d MiB", maxBytes/(1024*1024))
	default:
		return "无法保存上传文件"
	}
}
