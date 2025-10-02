package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"container-tags/internal/refs"
	"os"
    "log/slog"
)

var (
	// ErrNoMatchingTag is returned when no tag matches the target digest.
	ErrNoMatchingTag = errors.New("no matching tag")
)

// Client talks to a Docker Registry v2 API compatible registry.
type Client struct {
    http *http.Client
    // repo -> bearer token
    tokens map[string]string
    // slog logger (defaults to WARN level to stay quiet)
    logger *slog.Logger
    // Optional credentials for token exchange
    username     string
    password     string
    staticBearer string
}

func NewClient() *Client {
    return &Client{
        http:   &http.Client{Timeout: 20 * time.Second},
        tokens: make(map[string]string),
        logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
    }
}

// SetVerbosity controls logging level: 0 quiet (warn), 1 info, 2 debug.
func (c *Client) SetVerbosity(v int) {
    lvl := slog.LevelWarn
    if v >= 2 {
        lvl = slog.LevelDebug
    } else if v == 1 {
        lvl = slog.LevelInfo
    }
    c.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// SetLogger allows injecting a custom slog.Logger.
func (c *Client) SetLogger(l *slog.Logger) { c.logger = l }

// SetBasicAuth sets optional basic credentials used when exchanging tokens.
func (c *Client) SetBasicAuth(user, pass string) {
	c.username = user
	c.password = pass
}

// SetStaticBearer sets an explicit registry token to use directly.
func (c *Client) SetStaticBearer(tok string) { c.staticBearer = tok }

// ResolveTagAlias resolves which concrete tag (e.g., v1.2.3) has the same
// manifest digest as the provided reference tag (default "latest").
// It returns the digest for the reference tag and the matched concrete tag.
func (c *Client) ResolveTagAlias(img refs.ImageRef, referenceTag string) (string, string, error) {
	base := registryBase(img.Registry)
	if base == "" {
		return "", "", fmt.Errorf("unsupported registry: %s", img.Registry)
	}

	repo := img.Repository

	c.logInfo("registry=%s repo=%s refTag=%s base=%s", img.Registry, repo, referenceTag, base)

	// Fast path: infer version from labels on the reference tag's manifest/config.
	if d, v, ok, err := c.InferVersionFromTag(img, referenceTag); err == nil && ok {
		c.logInfo("inferred version %q from labels (digest %s)", v, d)
		return d, v, nil
	} else if err != nil {
		c.logDebug("infer version failed: %v", err)
	} else {
		c.logDebug("infer version: no version labels found")
	}

	// Get digest for the reference tag (e.g., latest)
	c.logInfo("fetching digest for %s:%s", repo, referenceTag)
	digest, err := c.headManifestDigest(context.Background(), base, repo, referenceTag)
	if err != nil {
		return "", "", err
	}
	c.logInfo("digest for %s:%s is %s", repo, referenceTag, digest)

	// List tags (paginated)
	tags, err := c.listAllTags(context.Background(), base, repo)
	if err != nil {
		return digest, "", err
	}
	c.logInfo("found %d tags", len(tags))

	// Prefer semver-looking tags first for speed/intent
	semverRe := regexp.MustCompile(`^(?:v)?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z\.-]+)?$`)
	var semverTags, otherTags []string
	for _, t := range tags {
		if t == referenceTag { // skip same tag
			continue
		}
		if strings.EqualFold(t, "latest") {
			continue
		}
		if semverRe.MatchString(t) {
			semverTags = append(semverTags, t)
		} else {
			otherTags = append(otherTags, t)
		}
	}

	// Check semver tags first
	for _, t := range semverTags {
		c.logDebug("checking semver tag %s", t)
		d, err := c.headManifestDigest(context.Background(), base, repo, t)
		if err != nil {
			c.logDebug("error checking %s: %v", t, err)
			continue // ignore individual tag errors and keep checking
		}
		if d == digest {
			c.logInfo("match: %s (digest %s)", t, d)
			return digest, t, nil
		}
	}

	// Fallback: check all other tags
	for _, t := range otherTags {
		c.logDebug("checking tag %s", t)
		d, err := c.headManifestDigest(context.Background(), base, repo, t)
		if err != nil {
			c.logDebug("error checking %s: %v", t, err)
			continue
		}
		if d == digest {
			c.logInfo("match: %s (digest %s)", t, d)
			return digest, t, nil
		}
	}

	return digest, "", ErrNoMatchingTag
}

// InferVersionFromTag attempts to read a version string for the given tag by
// inspecting manifest annotations and the image config labels. It returns the
// manifest digest, the inferred version, and whether a version was found.
func (c *Client) InferVersionFromTag(img refs.ImageRef, tag string) (digest string, version string, found bool, err error) {
	base := registryBase(img.Registry)
	repo := img.Repository
	ctx := context.Background()

	// GET manifest for the tag to obtain digest, content-type, and payload
	mURL := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, url.PathEscape(tag))
	c.logInfo("GET %s", mURL)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, mURL, nil)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := c.doWithAuth(ctx, base, repo, req)
	if err != nil {
		return "", "", false, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false, fmt.Errorf("manifest GET %s: %s", tag, resp.Status)
	}
	digest = resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		c.logDebug("no Docker-Content-Digest header on GET; will still parse payload")
	}
	ct := resp.Header.Get("Content-Type")
	c.logDebug("manifest content-type=%s digest=%s", ct, digest)

	// Try manifest index first
	if strings.Contains(ct, "application/vnd.oci.image.index.v1+json") || strings.Contains(ct, "application/vnd.docker.distribution.manifest.list.v2+json") {
		// Minimal index type
        var idx struct {
            Annotations map[string]string `json:"annotations"`
            Manifests   []struct {
                Digest      string            `json:"digest"`
                MediaType   string            `json:"mediaType"`
                Annotations map[string]string `json:"annotations"`
                Platform    struct {
                    OS           string `json:"os"`
                    Architecture string `json:"architecture"`
                } `json:"platform"`
            } `json:"manifests"`
        }
        if err := json.Unmarshal(body, &idx); err != nil {
            return digest, "", false, fmt.Errorf("parse index: %w", err)
        }
        if v := pickVersionFromAnnotations(idx.Annotations); v != "" {
            return digest, v, true, nil
        }
        // Check per-manifest annotations for a version before fetching configs
        for _, m := range idx.Manifests {
            if v := pickVersionFromAnnotations(m.Annotations); v != "" {
                return digest, v, true, nil
            }
        }
		// Choose linux/amd64 if present, else first
		chosen := ""
		for _, m := range idx.Manifests {
			if strings.EqualFold(m.Platform.OS, "linux") && strings.EqualFold(m.Platform.Architecture, "amd64") {
				chosen = m.Digest
				break
			}
		}
		if chosen == "" && len(idx.Manifests) > 0 {
			chosen = idx.Manifests[0].Digest
		}
        if chosen == "" {
            return digest, "", false, nil
        }
        // Try preferred manifest first; if not found, try the rest.
        d2, v2, ok2, err2 := c.inferVersionFromManifestDigest(ctx, base, repo, chosen, digest)
        if err2 != nil {
            return d2, v2, ok2, err2
        }
        if ok2 {
            return d2, v2, true, nil
        }
        for _, m := range idx.Manifests {
            if m.Digest == chosen {
                continue
            }
            d3, v3, ok3, err3 := c.inferVersionFromManifestDigest(ctx, base, repo, m.Digest, digest)
            if err3 != nil {
                continue
            }
            if ok3 {
                return d3, v3, true, nil
            }
        }
        return digest, "", false, nil
	}

	// Otherwise, treat as single manifest
	return c.inferVersionFromManifestPayload(ctx, base, repo, body, digest)
}

func (c *Client) inferVersionFromManifestDigest(ctx context.Context, base, repo, manifestDigest, outerDigest string) (string, string, bool, error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, url.PathEscape(manifestDigest))
	c.logInfo("GET %s", u)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := c.doWithAuth(ctx, base, repo, req)
	if err != nil {
		return outerDigest, "", false, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return outerDigest, "", false, fmt.Errorf("manifest GET by digest: %s", resp.Status)
	}
	// Prefer this digest if header present
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
		outerDigest = d
	}
	return c.inferVersionFromManifestPayload(ctx, base, repo, body, outerDigest)
}

func (c *Client) inferVersionFromManifestPayload(ctx context.Context, base, repo string, body []byte, digest string) (string, string, bool, error) {
    // Minimal manifest type
    var man struct {
        Annotations map[string]string `json:"annotations"`
        Config      struct {
            Digest string `json:"digest"`
        } `json:"config"`
    }
    if err := json.Unmarshal(body, &man); err != nil {
        return digest, "", false, fmt.Errorf("parse manifest: %w", err)
    }
    if v := pickVersionFromAnnotations(man.Annotations); v != "" {
        return digest, v, true, nil
    }
	if man.Config.Digest == "" {
		return digest, "", false, nil
	}
	// Fetch image config blob and inspect labels
	bu := fmt.Sprintf("%s/v2/%s/blobs/%s", base, repo, url.PathEscape(man.Config.Digest))
	c.logInfo("GET %s", bu)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, bu, nil)
	resp, err := c.doWithAuth(ctx, base, repo, req)
	if err != nil {
		return digest, "", false, err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return digest, "", false, fmt.Errorf("config blob GET: %s", resp.Status)
	}
    // Docker/OCI image config structure has config.Labels
    // Be liberal in what we accept: Docker uses `Labels` and OCI uses `labels`.
    var cfg struct {
        Config struct {
            LabelsUpper map[string]string `json:"Labels"`
            LabelsLower map[string]string `json:"labels"`
            Env         []string          `json:"Env"`
        } `json:"config"`
        ConfigUpper struct {
            LabelsUpper map[string]string `json:"Labels"`
            LabelsLower map[string]string `json:"labels"`
        } `json:"Config"`
        LabelsUpper map[string]string `json:"Labels"`
        LabelsLower map[string]string `json:"labels"`
        ContainerConfig struct {
            LabelsUpper map[string]string `json:"Labels"`
            LabelsLower map[string]string `json:"labels"`
            Env         []string          `json:"Env"`
        } `json:"container_config"`
        History []struct {
            CreatedBy string `json:"created_by"`
            Comment   string `json:"comment"`
        } `json:"history"`
    }
    if err := json.Unmarshal(b, &cfg); err != nil {
        return digest, "", false, fmt.Errorf("parse config: %w", err)
    }
    // Merge possible label locations
    labels := map[string]string{}
    for k, v := range cfg.Config.LabelsUpper { labels[k] = v }
    for k, v := range cfg.Config.LabelsLower { labels[k] = v }
    for k, v := range cfg.ConfigUpper.LabelsUpper { labels[k] = v }
    for k, v := range cfg.ConfigUpper.LabelsLower { labels[k] = v }
    for k, v := range cfg.LabelsUpper { labels[k] = v }
    for k, v := range cfg.LabelsLower { labels[k] = v }
    for k, v := range cfg.ContainerConfig.LabelsUpper { labels[k] = v }
    for k, v := range cfg.ContainerConfig.LabelsLower { labels[k] = v }
    if len(labels) == 0 {
        c.logDebug("no labels found in config blob")
        return digest, "", false, nil
    }
    // Look for common version labels (and try to extract semver-looking values)
    keys := []string{
        "alpha.talos.dev/version",
        "org.opencontainers.image.version",
        "org.label-schema.version",
        "io.artifacthub.package.version",
        "app.kubernetes.io/version",
        "build.version",
        "vcs.tag",
        "org.opencontainers.image.ref.name",
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "version",
    }
    for _, k := range keys {
        if v, ok := labels[k]; ok {
            if vv := extractVersionFromString(v); vv != "" {
                c.logInfo("inferred from label key=%s value=%s", k, vv)
                return digest, vv, true, nil
            }
        }
    }

    // Heuristic: scan env for VERSION-like entries
    var envs [][]string
    if len(cfg.Config.Env) > 0 {
        envs = append(envs, cfg.Config.Env)
    }
    if len(cfg.ContainerConfig.Env) > 0 {
        envs = append(envs, cfg.ContainerConfig.Env)
    }
    for _, arr := range envs {
        for _, e := range arr {
            if i := strings.IndexByte(e, '='); i > 0 {
                key := strings.ToLower(strings.TrimSpace(e[:i]))
                val := strings.TrimSpace(e[i+1:])
                if strings.Contains(key, "version") {
                    if vv := extractVersionFromString(val); vv != "" {
                        c.logInfo("inferred from env %s=%s", key, vv)
                        return digest, vv, true, nil
                    }
                }
            }
        }
    }

    // Heuristic: scan history messages for semver-like tokens
    for _, h := range cfg.History {
        if vv := extractVersionFromString(h.CreatedBy); vv != "" {
            c.logInfo("inferred from history.created_by=%s", vv)
            return digest, vv, true, nil
        }
        if vv := extractVersionFromString(h.Comment); vv != "" {
            c.logInfo("inferred from history.comment=%s", vv)
            return digest, vv, true, nil
        }
    }
    return digest, "", false, nil
}

func pickVersionFromAnnotations(ann map[string]string) string {
    if ann == nil {
        return ""
    }
    // Try a set of likely annotation keys and extract semver-looking parts if needed
    for _, k := range []string{
        "org.opencontainers.image.version",
        "org.label-schema.version",
        "io.artifacthub.package.version",
        "app.kubernetes.io/version",
        "vcs.tag",
        "org.opencontainers.image.ref.name",
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "version",
    } {
        if vv := extractVersionFromString(ann[k]); vv != "" {
            return vv
        }
    }
    return ""
}

// extractVersionFromString attempts to normalize a label or annotation value into
// a tag-like version string. It accepts simple values (e.g., "v1.2.3") or
// extracts the first semver-looking token from longer strings (e.g., "talosctl v1.6.3").
func extractVersionFromString(s string) string {
    s = strings.TrimSpace(s)
    if s == "" || strings.EqualFold(s, "latest") {
        return ""
    }
    // Direct match is good enough
    semverRe := regexp.MustCompile(`(?i)\b(?:v)?\d+\.\d+\.\d+(?:[.-][0-9A-Za-z\.-]+)?\b`)
    if semverRe.MatchString(s) {
        m := semverRe.FindString(s)
        // preserve original case of 'v' if present
        return strings.TrimSpace(m)
    }
    // Some projects use refs/tags/<ver>
    if strings.Contains(s, "refs/tags/") {
        part := s[strings.LastIndex(s, "/")+1:]
        if semverRe.MatchString(part) {
            return semverRe.FindString(part)
        }
    }
    return ""
}

func registryBase(reg string) string {
	switch reg {
	case "docker.io":
		return "https://registry-1.docker.io"
	case "ghcr.io":
		return "https://ghcr.io"
	default:
		// Fallback: assume registry base is the hostname itself over HTTPS
		if strings.Contains(reg, "://") {
			return reg
		}
		return "https://" + reg
	}
}

func (c *Client) listAllTags(ctx context.Context, base, repo string) ([]string, error) {
	var tags []string
	// Use pagination where supported. Start with a decent page size.
	nextURL := fmt.Sprintf("%s/v2/%s/tags/list?n=1000", base, repo)
	for {
		c.logInfo("GET %s", nextURL)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := c.doWithAuth(ctx, base, repo, req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list tags failed: %s: %s", resp.Status, string(body))
		}
		var out struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		tags = append(tags, out.Tags...)
		c.logInfo("page returned %d tags (total %d)", len(out.Tags), len(tags))

        // Parse Link: <url>; rel="next"
        link := resp.Header.Get("Link")
        if link == "" {
            break
        }
		// Very small parser for RFC5988-style header
		// Example: <https://registry-1.docker.io/v2/library/nginx/tags/list?next_page=...>; rel="next"
		var next string
		for _, part := range strings.Split(link, ",") {
			p := strings.TrimSpace(part)
			if strings.HasSuffix(p, "rel=\"next\"") {
				if i := strings.Index(p, "<"); i != -1 {
					if j := strings.Index(p, ">"); j != -1 && j > i+1 {
						next = p[i+1 : j]
						break
					}
				}
			}
		}
        if next == "" {
            break
        }
        // Normalize next to absolute URL using base if it's relative
        if u, err := url.Parse(next); err == nil {
            if !u.IsAbs() {
                if bu, err2 := url.Parse(base); err2 == nil {
                    nextURL = bu.ResolveReference(u).String()
                } else {
                    nextURL = base + strings.TrimPrefix(next, "/")
                }
            } else {
                nextURL = u.String()
            }
        } else {
            // Fallback: best-effort join
            if strings.HasPrefix(next, "/") {
                nextURL = base + next
            } else {
                nextURL = base + "/" + next
            }
        }
        c.logDebug("pagination next resolved=%s", nextURL)
	}
	return tags, nil
}

func (c *Client) headManifestDigest(ctx context.Context, base, repo, reference string) (string, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, url.PathEscape(reference))
	c.logDebug("HEAD %s", url)
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	// Ask for both OCI and Docker schema2 manifests and indexes
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))

	resp, err := c.doWithAuth(ctx, base, repo, req)
	if err != nil {
		return "", err
	}
	// Some registries may not allow HEAD; fallback to GET to extract headers.
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		c.logDebug("fallback to GET for %s", url)
		req.Method = http.MethodGet
		resp, err = c.doWithAuth(ctx, base, repo, req)
		if err != nil {
			return "", err
		}
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK { // GET returns 200; HEAD often returns 200 as well
		return "", fmt.Errorf("manifest %s: %s", reference, resp.Status)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("manifest %s: missing digest header", reference)
	}
	return digest, nil
}

func (c *Client) doWithAuth(ctx context.Context, base, repo string, req *http.Request) (*http.Response, error) {
	// Attach token if we already have one
	if tok := c.tokens[repo]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if c.staticBearer != "" {
		// Try with provided static bearer first.
		req.Header.Set("Authorization", "Bearer "+c.staticBearer)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Parse WWW-Authenticate to obtain a token
	www := resp.Header.Get("Www-Authenticate")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if www == "" {
		return nil, fmt.Errorf("unauthorized and no authenticate challenge")
	}
	realm, service, scope, err := parseAuthChallenge(www, repo)
	if err != nil {
		return nil, err
	}
	c.logInfo("authenticating realm=%s service=%s scope=%s", realm, service, scope)
	tok, err := fetchToken(ctx, realm, service, scope, c.username, c.password)
	if err != nil {
		return nil, err
	}
	c.tokens[repo] = tok

	// Retry request once with token
	req2 := req.Clone(ctx)
	req2.Header.Set("Authorization", "Bearer "+tok)
	return c.http.Do(req2)
}

func parseAuthChallenge(h, repo string) (realm, service, scope string, err error) {
	// Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "bearer ") {
		return "", "", "", fmt.Errorf("unsupported auth challenge: %s", h)
	}
	params := map[string]string{}
	rest := strings.TrimSpace(h[len("Bearer "):])
	for _, p := range splitCSVRespectQuotes(rest) {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.Trim(kv[1], "\"")
		params[key] = val
	}
	realm = params["realm"]
	service = params["service"]
	scope = params["scope"]
	if realm == "" {
		return "", "", "", fmt.Errorf("missing realm in auth challenge")
	}
	// If scope wasn't provided, default to repository:repo:pull
	if scope == "" && repo != "" {
		scope = fmt.Sprintf("repository:%s:pull", repo)
	}
	return
}

func splitCSVRespectQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case ',':
			if inQ {
				cur.WriteByte(ch)
			} else {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func fetchToken(ctx context.Context, realm, service, scope, user, pass string) (string, error) {
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s: %s", resp.Status, string(body))
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	tok := out.Token
	if tok == "" {
		tok = out.AccessToken
	}
	if tok == "" {
		return "", fmt.Errorf("no token in response")
	}
	return tok, nil
}

func (c *Client) logInfo(format string, a ...any) {
    if c.logger != nil {
        c.logger.Info(fmt.Sprintf(format, a...))
    }
}

func (c *Client) logDebug(format string, a ...any) {
    if c.logger != nil {
        c.logger.Debug(fmt.Sprintf(format, a...))
    }
}
