package media

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	maxUploadSizeBytes = 10 << 20
)

type UploadHandler struct {
	uploader ImageUploader
}

type ImageUploader interface {
	UploadImage(ctx context.Context, imageSource string) (string, error)
}

func NewUploadHandler(uploader ImageUploader) *UploadHandler {
	return &UploadHandler{uploader: uploader}
}

func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if h.uploader == nil {
		writeError(w, http.StatusInternalServerError, "image uploader is not configured")
		return
	}

	if err := r.ParseMultipartForm(maxUploadSizeBytes); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxUploadSizeBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read file")
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "file is empty")
		return
	}
	if len(data) > maxUploadSizeBytes {
		writeError(w, http.StatusBadRequest, "file is too large")
		return
	}

	contentType := strings.TrimSpace(header.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	if !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		writeError(w, http.StatusBadRequest, "file must be an image")
		return
	}

	imageSource := fmt.Sprintf("data:%s;base64,%s", contentType, base64.StdEncoding.EncodeToString(data))
	secureURL, err := h.uploader.UploadImage(r.Context(), imageSource)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to upload image")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"secure_url": secureURL})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
