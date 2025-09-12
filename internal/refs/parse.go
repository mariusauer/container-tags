package refs

import (
	"fmt"
	"strings"
)

// ImageRef represents a parsed container image reference.
type ImageRef struct {
	Registry   string
	Repository string // without registry, e.g., "library/nginx" or "owner/app"
	Tag        string // may be empty; default to "latest"
}

// Parse parses an image reference like:
//
//	nginx
//	library/nginx
//	docker.io/library/nginx:latest
//	ghcr.io/owner/app:latest
//
// If no registry is provided, defaults to docker.io.
// For docker.io, if no namespace is provided, defaults to library/.
func Parse(s string) (ImageRef, error) {
	var ref ImageRef
	s = strings.TrimSpace(s)
	if s == "" {
		return ref, fmt.Errorf("empty image reference")
	}

	// Split tag (if any)
	var name, tag string
	if i := strings.LastIndex(s, ":"); i != -1 && !strings.Contains(s[i+1:], "/") {
		name = s[:i]
		tag = s[i+1:]
	} else {
		name = s
		tag = ""
	}

	parts := strings.Split(name, "/")
	if len(parts) == 1 {
		// No registry, no namespace
		ref.Registry = "docker.io"
		ref.Repository = "library/" + parts[0]
	} else if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
		// Has registry component
		ref.Registry = parts[0]
		ref.Repository = strings.Join(parts[1:], "/")
		if ref.Registry == "docker.io" && !strings.Contains(ref.Repository, "/") {
			ref.Repository = "library/" + ref.Repository
		}
	} else {
		// No registry; default to docker.io
		ref.Registry = "docker.io"
		ref.Repository = strings.Join(parts, "/")
		if !strings.Contains(ref.Repository, "/") {
			ref.Repository = "library/" + ref.Repository
		}
	}

	ref.Tag = tag
	return ref, nil
}

// String renders an image reference without tag, normalized with registry.
func String(i ImageRef) string {
	return i.Registry + "/" + i.Repository
}
