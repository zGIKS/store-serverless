package media

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Cloudinary struct {
	apiKey     string
	apiSecret  string
	uploadURL  string
	httpClient *http.Client
}

type cloudinaryUploadResponse struct {
	SecureURL string `json:"secure_url"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func NewCloudinary(rawURL string) (*Cloudinary, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("parse cloudinary url: %w", err)
	}

	if parsed.Scheme != "cloudinary" {
		return nil, fmt.Errorf("invalid cloudinary scheme")
	}

	apiKey := parsed.User.Username()
	apiSecret, ok := parsed.User.Password()
	if !ok {
		return nil, fmt.Errorf("missing cloudinary api secret")
	}
	cloudName := parsed.Hostname()
	if apiKey == "" || apiSecret == "" || cloudName == "" {
		return nil, fmt.Errorf("invalid cloudinary credentials")
	}

	return &Cloudinary{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		uploadURL: fmt.Sprintf("https://api.cloudinary.com/v1_1/%s/image/upload", cloudName),
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func (c *Cloudinary) UploadImage(ctx context.Context, imageSource string) (string, error) {
	imageSource = strings.TrimSpace(imageSource)
	if imageSource == "" {
		return "", fmt.Errorf("empty image source")
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := c.sign(timestamp)

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		if err := writer.WriteField("file", imageSource); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("write file field: %w", err))
			return
		}
		if err := writer.WriteField("timestamp", timestamp); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("write timestamp field: %w", err))
			return
		}
		if err := writer.WriteField("api_key", c.apiKey); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("write api_key field: %w", err))
			return
		}
		if err := writer.WriteField("signature", signature); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("write signature field: %w", err))
			return
		}
		if err := writer.Close(); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("close multipart writer: %w", err))
			return
		}
		_ = pw.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.uploadURL, pr)
	if err != nil {
		return "", fmt.Errorf("build cloudinary upload request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cloudinary upload request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", fmt.Errorf("read cloudinary response: %w", err)
	}

	var parsedResp cloudinaryUploadResponse
	if err := json.Unmarshal(body, &parsedResp); err != nil {
		return "", fmt.Errorf("decode cloudinary response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if parsedResp.Error != nil && parsedResp.Error.Message != "" {
			return "", fmt.Errorf("cloudinary upload failed: %s", parsedResp.Error.Message)
		}
		return "", fmt.Errorf("cloudinary upload failed with status %d", resp.StatusCode)
	}

	if parsedResp.SecureURL == "" {
		return "", fmt.Errorf("cloudinary response missing secure_url")
	}

	return parsedResp.SecureURL, nil
}

func (c *Cloudinary) sign(timestamp string) string {
	h := sha1.New() // #nosec G401: cloudinary API signature requires SHA-1.
	_, _ = h.Write([]byte("timestamp=" + timestamp + c.apiSecret))
	return hex.EncodeToString(h.Sum(nil))
}
