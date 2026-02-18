package product

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
)

var allowedURLChars = regexp.MustCompile(`^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$`)
var allowedHost = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

const maxJSONBodyBytes = 1 << 20

type Handler struct {
	repo     *Repository
	uploader ImageUploader
}

type ImageUploader interface {
	UploadImage(ctx context.Context, imageSource string) (string, error)
}

func NewHandler(repo *Repository, uploader ImageUploader) *Handler {
	return &Handler{repo: repo, uploader: uploader}
}

func (h *Handler) ListProducts(w http.ResponseWriter, r *http.Request) {
	products, err := h.repo.List(r.Context())
	if err != nil {
		sentry.CaptureException(err)
		writeError(w, http.StatusInternalServerError, "failed to list products")
		return
	}

	writeJSON(w, http.StatusOK, products)
}

func (h *Handler) CreateProduct(w http.ResponseWriter, r *http.Request) {
	if h.uploader == nil {
		writeError(w, http.StatusInternalServerError, "image uploader is not configured")
		return
	}

	input, ok := parseInput(w, r)
	if !ok {
		return
	}

	uploadedURL, err := h.uploader.UploadImage(r.Context(), input.ImageURL)
	if err != nil {
		sentry.CaptureException(err)
		writeError(w, http.StatusBadGateway, "failed to upload image")
		return
	}
	input.ImageURL = uploadedURL

	p, err := h.repo.Create(r.Context(), input)
	if err != nil {
		sentry.CaptureException(err)
		writeError(w, http.StatusInternalServerError, "failed to create product")
		return
	}

	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	if h.uploader == nil {
		writeError(w, http.StatusInternalServerError, "image uploader is not configured")
		return
	}

	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid product id")
		return
	}

	input, ok := parseInput(w, r)
	if !ok {
		return
	}

	uploadedURL, err := h.uploader.UploadImage(r.Context(), input.ImageURL)
	if err != nil {
		sentry.CaptureException(err)
		writeError(w, http.StatusBadGateway, "failed to upload image")
		return
	}
	input.ImageURL = uploadedURL

	p, err := h.repo.Update(r.Context(), id, input)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "product not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update product")
		sentry.CaptureException(err)
		return
	}

	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid product id")
		return
	}

	err := h.repo.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "product not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete product")
		sentry.CaptureException(err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func parseInput(w http.ResponseWriter, r *http.Request) (ProductInput, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)

	var input ProductInput
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return ProductInput{}, false
	}

	input.Title = strings.TrimSpace(input.Title)
	input.Description = strings.TrimSpace(input.Description)
	input.ImageURL = strings.TrimSpace(input.ImageURL)

	if input.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return ProductInput{}, false
	}
	if !utf8.ValidString(input.Title) || len(input.Title) > 150 {
		writeError(w, http.StatusBadRequest, "title is invalid")
		return ProductInput{}, false
	}
	if !utf8.ValidString(input.Description) || len(input.Description) > 1000 {
		writeError(w, http.StatusBadRequest, "description is invalid")
		return ProductInput{}, false
	}
	if input.ImageURL == "" {
		writeError(w, http.StatusBadRequest, "image_url is required")
		return ProductInput{}, false
	}
	if len(input.ImageURL) > 500 || !isASCII(input.ImageURL) {
		writeError(w, http.StatusBadRequest, "image_url contains invalid characters")
		return ProductInput{}, false
	}
	if !allowedURLChars.MatchString(input.ImageURL) {
		writeError(w, http.StatusBadRequest, "image_url contains invalid characters")
		return ProductInput{}, false
	}
	parsedURL, err := url.ParseRequestURI(input.ImageURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		writeError(w, http.StatusBadRequest, "image_url must be a valid link")
		return ProductInput{}, false
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		writeError(w, http.StatusBadRequest, "image_url must start with http or https")
		return ProductInput{}, false
	}
	if parsedURL.User != nil || !allowedHost.MatchString(parsedURL.Hostname()) {
		writeError(w, http.StatusBadRequest, "image_url host is invalid")
		return ProductInput{}, false
	}
	if input.Price < 0 {
		writeError(w, http.StatusBadRequest, "price must be >= 0")
		return ProductInput{}, false
	}

	return input, true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}
