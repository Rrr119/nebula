package nebula

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/slackhq/nebula/config"
)

// tagSelector is the compiled form of a named tag defined under `firewall.tags`.
// A tag is a shorthand for the remote selector portion of a firewall rule
// (host, group/groups, or cidr) so that policy can be written once and
// referenced by name from any number of inbound or outbound rules.
type tagSelector struct {
	Host   string
	Groups []string
	Cidr   string
}

// parseFirewallTags reads the optional `firewall.tags` map and compiles each
// entry into a tagSelector. Tag definitions may only contain remote selectors
// (host, group, groups, cidr); ports, protos, local_cidr, CA constraints, and
// references to other tags are rejected.
func parseFirewallTags(l *slog.Logger, c *config.C) (map[string]tagSelector, error) {
	raw := c.Get("firewall.tags")
	if raw == nil {
		return nil, nil
	}

	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("firewall.tags failed to parse, should be a map of tag name to selector")
	}

	tags := make(map[string]tagSelector, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		sel, err := parseTagSelector(l, name, m[name])
		if err != nil {
			return nil, err
		}
		tags[name] = sel
	}

	return tags, nil
}

func parseTagSelector(l *slog.Logger, name string, v any) (tagSelector, error) {
	var sel tagSelector

	r, err := convertRule(l, v, "firewall.tags."+name, 0)
	if err != nil {
		return sel, fmt.Errorf("firewall.tags.%s; %s", name, err)
	}

	if r.Port != "" || r.Code != "" || r.Proto != "" || r.LocalCidr != "" || r.CAName != "" || r.CASha != "" {
		return sel, fmt.Errorf("firewall.tags.%s; only host, group, groups, and cidr may be used in a tag definition", name)
	}

	if len(r.Tags) > 0 {
		return sel, fmt.Errorf("firewall.tags.%s; tags cannot reference other tags", name)
	}

	if r.Host == "" && len(r.Groups) == 0 && r.Cidr == "" {
		return sel, fmt.Errorf("firewall.tags.%s; at least one of host, group, or cidr must be provided", name)
	}

	if r.Cidr != "" && r.Cidr != "any" {
		if _, err := netip.ParsePrefix(r.Cidr); err != nil {
			return sel, fmt.Errorf("firewall.tags.%s; cidr did not parse; %s", name, err)
		}
	}

	sel.Host = r.Host
	sel.Groups = r.Groups
	sel.Cidr = r.Cidr
	return sel, nil
}

// compileTagRules expands a rule that references tags into one or more
// concrete rules that only use the primitive selectors (host, groups, cidr).
// A rule's own selectors, if any, are kept as an additional alternative,
// preserving the OR semantics of the existing firewall evaluation. Port,
// proto, local_cidr, and CA constraints are inherited by every compiled rule.
func compileTagRules(r rule, tags map[string]tagSelector) ([]rule, error) {
	if len(r.Tags) == 0 {
		return []rule{r}, nil
	}

	compiled := make([]rule, 0, len(r.Tags)+1)
	if r.Host != "" || len(r.Groups) > 0 || r.Cidr != "" {
		base := r
		base.Tags = nil
		compiled = append(compiled, base)
	}

	seen := make(map[string]struct{}, len(r.Tags))
	for _, name := range r.Tags {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}

		sel, ok := tags[name]
		if !ok {
			return nil, fmt.Errorf("tag `%s` is not defined in firewall.tags", name)
		}

		nr := r
		nr.Tags = nil
		nr.Host = sel.Host
		nr.Groups = sel.Groups
		nr.Cidr = sel.Cidr
		compiled = append(compiled, nr)
	}

	return compiled, nil
}
