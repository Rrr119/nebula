package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFirewallTags(t *testing.T) {
	l := test.NewLogger()

	// No tags defined is valid and compatible with existing configs
	conf := config.NewC(l)
	conf.Settings["firewall"] = map[string]any{}
	tags, err := parseFirewallTags(l, conf)
	require.NoError(t, err)
	assert.Nil(t, tags)

	// Happy path, all selector forms
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"tags": map[string]any{
		"web":   map[string]any{"groups": []any{"web"}},
		"alice": map[string]any{"host": "alice-laptop"},
		"corp":  map[string]any{"cidr": "10.0.0.0/8"},
		"any":   map[string]any{"group": "any"},
	}}
	tags, err = parseFirewallTags(l, conf)
	require.NoError(t, err)
	assert.Equal(t, tagSelector{Groups: []string{"web"}}, tags["web"])
	assert.Equal(t, tagSelector{Host: "alice-laptop"}, tags["alice"])
	assert.Equal(t, tagSelector{Cidr: "10.0.0.0/8"}, tags["corp"])
	assert.Equal(t, tagSelector{Groups: []string{"any"}}, tags["any"])

	// Not a map
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"tags": "nope"}
	_, err = parseFirewallTags(l, conf)
	require.EqualError(t, err, "firewall.tags failed to parse, should be a map of tag name to selector")

	// Empty selector
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"tags": map[string]any{"empty": map[string]any{}}}
	_, err = parseFirewallTags(l, conf)
	require.EqualError(t, err, "firewall.tags.empty; at least one of host, group, or cidr must be provided")

	// Ports, protos, local_cidr, and CA constraints are not allowed in a tag
	for k, v := range map[string]any{
		"port":       "80",
		"proto":      "tcp",
		"local_cidr": "10.0.0.0/8",
		"ca_name":    "ca",
		"ca_sha":     "sha",
	} {
		conf = config.NewC(l)
		conf.Settings["firewall"] = map[string]any{"tags": map[string]any{
			"bad": map[string]any{"host": "a", k: v},
		}}
		_, err = parseFirewallTags(l, conf)
		require.EqualError(t, err, "firewall.tags.bad; only host, group, groups, and cidr may be used in a tag definition", "%s", k)
	}

	// Tags cannot reference other tags
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"tags": map[string]any{
		"web": map[string]any{"groups": []any{"web"}},
		"bad": map[string]any{"tag": "web"},
	}}
	_, err = parseFirewallTags(l, conf)
	require.EqualError(t, err, "firewall.tags.bad; tags cannot reference other tags")

	// Bad cidr
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"tags": map[string]any{
		"bad": map[string]any{"cidr": "junk/junk"},
	}}
	_, err = parseFirewallTags(l, conf)
	require.EqualError(t, err, `firewall.tags.bad; cidr did not parse; netip.ParsePrefix("junk/junk"): ParseAddr("junk"): unable to parse IP`)
}

func TestAddFirewallRulesFromConfig_Tags(t *testing.T) {
	l := test.NewLogger()

	tagDefs := func() map[string]any {
		return map[string]any{
			"web": map[string]any{"groups": []any{"web"}},
			"db":  map[string]any{"groups": []any{"db"}},
		}
	}

	// A single tag compiles to the tagged selector
	conf := config.NewC(l)
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "443", "proto": "tcp", "tag": "web"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 1)
	assert.Equal(t, addRuleCall{incoming: true, proto: iputil.IPProtocolTCP, startPort: 443, endPort: 443, groups: []string{"web"}}, mf.calls[0])

	// Multiple tags compile to one rule each, inheriting port/proto/local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "any", "proto": "any", "tags": []any{"web", "db"}, "local_cidr": "10.0.0.0/8"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 2)
	assert.Equal(t, []string{"web"}, mf.calls[0].groups)
	assert.Equal(t, "10.0.0.0/8", mf.calls[0].localIp)
	assert.Equal(t, []string{"db"}, mf.calls[1].groups)
	assert.Equal(t, "10.0.0.0/8", mf.calls[1].localIp)

	// A rule's own selectors are kept as an additional alternative
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "host": "bastion", "tag": "web"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 2)
	assert.Equal(t, "bastion", mf.calls[0].host)
	assert.Equal(t, []string{"web"}, mf.calls[1].groups)

	// Duplicate tags only compile once
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tags": []any{"web", "web"}}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 1)

	// tags accepts a single string value
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tags": "web"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 1)
	assert.Equal(t, []string{"web"}, mf.calls[0].groups)

	// Undefined tag
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tag": "nope"}},
	}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; tag `nope` is not defined in firewall.tags")

	// Tag referenced without any tag definitions
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tag": "web"}},
	}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; tag `web` is not defined in firewall.tags")

	// Both tag and tags
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tag": "web", "tags": []any{"db"}}},
	}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; only one of tag or tags should be defined, both provided")

	// A null tag with nothing else is refused, it would match any host
	for _, key := range []string{"tag", "tags"} {
		conf = config.NewC(l)
		mf = &mockFirewall{}
		conf.Settings["firewall"] = map[string]any{
			"tags":    tagDefs(),
			"inbound": []any{map[string]any{"port": "1", "proto": "any", key: nil, "ca_name": "x"}},
		}
		require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; "+key+" is null and no host, group, tag, or cidr was provided, use `host: any` to match any host", "%s", key)
	}

	// A null tag alongside a host is the same as not providing it
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "tag": nil, "host": "a"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 1)
	assert.Equal(t, "a", mf.calls[0].host)

	// A null group alongside a tag uses the tag
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":    tagDefs(),
		"inbound": []any{map[string]any{"port": "1", "proto": "any", "group": nil, "tag": "web"}},
	}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	require.Len(t, mf.calls, 1)
	assert.Equal(t, []string{"web"}, mf.calls[0].groups)

	// Invalid tag definitions fail even when only loading the opposite table
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{
		"tags":     map[string]any{"bad": map[string]any{}},
		"outbound": []any{map[string]any{"port": "1", "proto": "any", "host": "a"}},
	}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.tags.bad; at least one of host, group, or cidr must be provided")
}

// TestFirewall_TagsDrop proves tag based rules compiled from config enforce
// the same way as hand written group rules.
func TestFirewall_TagsDrop(t *testing.T) {
	l := test.NewLogger()
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	myCert := &dummyCert{
		name:     "me",
		networks: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/8")},
	}

	webCert := &dummyCert{
		name:     "web-1",
		networks: []netip.Prefix{netip.MustParsePrefix("1.1.1.2/32")},
		groups:   []string{"web"},
	}
	webH := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    webCert,
				InvertedGroups: map[string]struct{}{"web": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("1.1.1.2")},
	}
	webH.buildNetworks(myVpnNetworksTable, webCert)

	dbCert := &dummyCert{
		name:     "db-1",
		networks: []netip.Prefix{netip.MustParsePrefix("1.1.1.3/32")},
		groups:   []string{"db"},
	}
	dbH := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    dbCert,
				InvertedGroups: map[string]struct{}{"db": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("1.1.1.3")},
	}
	dbH.buildNetworks(myVpnNetworksTable, dbCert)

	conf := config.NewC(l)
	conf.Settings["firewall"] = map[string]any{
		"tags": map[string]any{
			"web-tier": map[string]any{"groups": []any{"web"}},
		},
		"inbound": []any{
			map[string]any{"port": "80", "proto": "udp", "tag": "web-tier"},
		},
	}

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert)
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, fw))
	cp := cert.NewCAPool()

	packet := func(remote string, port uint16) firewall.Packet {
		return firewall.Packet{
			LocalAddr:  netip.MustParseAddr("1.1.1.1"),
			RemoteAddr: netip.MustParseAddr(remote),
			LocalPort:  port,
			RemotePort: 9000,
			Protocol:   iputil.IPProtocolUDP,
		}
	}

	// web tier is allowed on port 80
	assert.NoError(t, fw.Drop(packet("1.1.1.2", 80), true, &webH, cp, nil))
	// web tier is denied on any other port
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(packet("1.1.1.2", 81), true, &webH, cp, nil))
	// db tier matches no tag and is denied
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(packet("1.1.1.3", 80), true, &dbH, cp, nil))
}
