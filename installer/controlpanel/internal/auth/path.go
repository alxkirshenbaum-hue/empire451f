package auth

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Config is fixed before serving; frontend strips BasePath before Unix API requests.
type Config struct{ Origin, BasePath string }

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)
var basePattern = regexp.MustCompile(`^/[0-9a-f]{32}/$`)

func ParseConfig(origin, base string) (Config, error) {
	if origin == "" {
		origin = Origin
	}
	if base == "" {
		base = "/"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || !domainPattern.MatchString(u.Host) || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || origin != "https://"+u.Host {
		return Config{}, errors.New("invalid PANEL_ORIGIN: canonical HTTPS DNS origin required")
	}
	if len(u.Host) > 253 || net.ParseIP(u.Host) != nil {
		return Config{}, errors.New("invalid PANEL_ORIGIN hostname")
	}
	for _, label := range strings.Split(u.Host, ".") {
		if len(label) > 63 {
			return Config{}, errors.New("invalid PANEL_ORIGIN label")
		}
	}
	if base != "/" && !basePattern.MatchString(base) {
		return Config{}, errors.New("invalid PANEL_BASE_PATH")
	}
	return Config{Origin: origin, BasePath: base}, nil
}

// Configure must be called before Handler, using validated startup configuration.
func (s *Service) Configure(c Config) { s.config = c }
func (s *Service) Config() Config {
	if s.config.Origin == "" {
		return Config{Origin: Origin, BasePath: "/"}
	}
	return s.config
}
func (s *Service) cookie(value string, age int) *http.Cookie {
	c := cookie(value, age)
	c.Path = s.Config().BasePath
	return c
}
