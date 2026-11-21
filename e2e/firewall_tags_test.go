//go:build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestFirewallTags is a three node test for tag based firewall policy. `me`
// compiles a tag (`web-tier` -> group `web`) into its inbound rules. Traffic
// from the tagged web node on the allowed port passes, traffic from the same
// node on another port and traffic from the untagged db node is dropped.
func TestFirewallTags(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	newCert := func(name, vpnNet string, groups []string) (cert.Certificate, []byte, []byte) {
		c, _, priv, pem := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, name, time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix(vpnNet)}, nil, groups)
		return c, priv, pem
	}

	myCert, myPrivKey, myCertPem := newCert("me", "10.128.0.1/24", nil)
	webCert, webPrivKey, _ := newCert("web", "10.128.0.2/24", []string{"web"})
	dbCert, dbPrivKey, _ := newCert("db", "10.128.0.3/24", []string{"db"})

	myControl, myVpnIpNet, myUdpAddr, myC := newServer([]cert.Certificate{ca}, []cert.Certificate{myCert}, myPrivKey, m{})
	webControl, webVpnIpNet, webUdpAddr, _ := newServer([]cert.Certificate{ca}, []cert.Certificate{webCert}, webPrivKey, m{})
	dbControl, dbVpnIpNet, dbUdpAddr, _ := newServer([]cert.Certificate{ca}, []cert.Certificate{dbCert}, dbPrivKey, m{})

	// Replace the default allow-any firewall on `me` with a tag based policy,
	// proving the new config coexists with the existing reload machinery
	mc := m{
		"pki": m{
			"ca":   string(caPem),
			"cert": string(myCertPem),
			"key":  string(myPrivKey),
		},
		"firewall": m{
			"tags": m{
				"web-tier": m{"groups": []string{"web"}},
			},
			"inbound": []m{{
				"proto": "udp",
				"port":  "80",
				"tag":   "web-tier",
			}},
			"outbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
		},
		"listen":  myC.Settings["listen"],
		"logging": myC.Settings["logging"],
		"timers":  myC.Settings["timers"],
	}
	cb, err := yaml.Marshal(mc)
	require.NoError(t, err)
	require.NoError(t, myC.ReloadConfigString(string(cb)).Err)

	// Share underlay information, web and db do not need to know of each other
	myControl.InjectLightHouseAddr(webVpnIpNet[0].Addr(), webUdpAddr)
	myControl.InjectLightHouseAddr(dbVpnIpNet[0].Addr(), dbUdpAddr)
	webControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)
	dbControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	webControl.Start()
	dbControl.Start()

	r := router.NewR(t, myControl, webControl, dbControl)
	defer r.RenderFlow()

	r.Log("web is tagged web-tier, udp/80 to me should pass the tag rule")
	webControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, webVpnIpNet[0].Addr(), 8080, []byte("hi from web")))
	p := r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("hi from web"), p, webVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 8080, 80)

	r.Log("web on udp/81 matches no tag rule and should be dropped")
	webControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 81, webVpnIpNet[0].Addr(), 8080, []byte("web on 81")))
	r.RouteFor(2 * time.Second)
	assert.Nil(t, myControl.GetFromTun(false), "untagged port should not pass the firewall")

	r.Log("db is not in the web-tier tag, udp/80 to me should be dropped")
	dbControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, dbVpnIpNet[0].Addr(), 8080, []byte("hi from db")))
	r.RouteFor(2 * time.Second)
	assert.Nil(t, myControl.GetFromTun(false), "untagged host should not pass the firewall")

	r.Log("web can still reach me on udp/80 after the drops")
	webControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, webVpnIpNet[0].Addr(), 8081, []byte("web again")))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("web again"), p, webVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 8081, 80)

	myControl.Stop()
	webControl.Stop()
	dbControl.Stop()
}
