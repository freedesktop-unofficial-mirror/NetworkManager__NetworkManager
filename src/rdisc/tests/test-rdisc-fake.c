/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* rdisc.c - test program
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <syslog.h>

#include "nm-rdisc.h"
#include "nm-fake-rdisc.h"
#include "nm-logging.h"

#include "nm-fake-platform.h"

static NMFakeRDisc *
rdisc_new (void)
{
	NMRDisc *rdisc;
	const int ifindex = 1;
	const char *ifname = nm_platform_link_get_name (ifindex);

	rdisc = nm_fake_rdisc_new (ifindex, ifname);
	g_assert (rdisc);
	return NM_FAKE_RDISC (rdisc);
}

static void
match_gateway (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt, NMRDiscPreference pref)
{
	NMRDiscGateway *gw = &g_array_index (array, NMRDiscGateway, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &gw->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (gw->timestamp, ==, ts);
	g_assert_cmpint (gw->lifetime, ==, lt);
	g_assert_cmpint (gw->preference, ==, pref);
}

static void
match_address (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt, guint32 preferred)
{
	NMRDiscAddress *a = &g_array_index (array, NMRDiscAddress, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &a->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (a->timestamp, ==, ts);
	g_assert_cmpint (a->lifetime, ==, lt);
	g_assert_cmpint (a->preferred, ==, preferred);
}

static void
match_route (GArray *array, guint idx, const char *nw, int plen, const char *gw, guint32 ts, guint32 lt, NMRDiscPreference pref)
{
	NMRDiscRoute *route = &g_array_index (array, NMRDiscRoute, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &route->network, buf, sizeof (buf)), ==, nw);
	g_assert_cmpint (route->plen, ==, plen);
	g_assert_cmpstr (inet_ntop (AF_INET6, &route->gateway, buf, sizeof (buf)), ==, gw);
	g_assert_cmpint (route->timestamp, ==, ts);
	g_assert_cmpint (route->lifetime, ==, lt);
	g_assert_cmpint (route->preference, ==, pref);
}

static void
match_dns_server (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt)
{
	NMRDiscDNSServer *dns = &g_array_index (array, NMRDiscDNSServer, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &dns->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (dns->timestamp, ==, ts);
	g_assert_cmpint (dns->lifetime, ==, lt);
}

static void
match_dns_domain (GArray *array, guint idx, const char *domain, guint32 ts, guint32 lt)
{
	NMRDiscDNSDomain *dns = &g_array_index (array, NMRDiscDNSDomain, idx);

	g_assert_cmpstr (dns->domain, ==, domain);
	g_assert_cmpint (dns->timestamp, ==, ts);
	g_assert_cmpint (dns->lifetime, ==, lt);
}

typedef struct {
	GMainLoop *loop;
	guint counter;
	guint rs_counter;
	guint32 timestamp1;
} TestData;

static void
test_simple_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
{
	g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_DHCP_LEVEL |
	                              NM_RDISC_CONFIG_GATEWAYS |
	                              NM_RDISC_CONFIG_ADDRESSES |
	                              NM_RDISC_CONFIG_ROUTES |
	                              NM_RDISC_CONFIG_DNS_SERVERS |
	                              NM_RDISC_CONFIG_DNS_DOMAINS |
	                              NM_RDISC_CONFIG_HOP_LIMIT |
	                              NM_RDISC_CONFIG_MTU);
	g_assert_cmpint (rdisc->dhcp_level, ==, NM_RDISC_DHCP_LEVEL_OTHERCONF);
	match_gateway (rdisc->gateways, 0, "fe80::1", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
	match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
	match_route (rdisc->routes, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
	match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::1", data->timestamp1, 10);
	match_dns_domain (rdisc->dns_domains, 0, "foobar.com", data->timestamp1, 10);

	g_assert (nm_fake_rdisc_done (NM_FAKE_RDISC (rdisc)));
	data->counter++;
	g_main_loop_quit (data->loop);
}

static void
test_simple (void)
{
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_rdisc_add_ra (rdisc, 3, NM_RDISC_DHCP_LEVEL_OTHERCONF, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 10);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_simple_changed),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 1);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

static void
test_everything_rs_sent (NMRDisc *rdisc, TestData *data)
{
	g_assert_cmpint (data->rs_counter, ==, 0);
	data->rs_counter++;
}

static void
test_everything_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
{
	if (data->counter == 0) {
		g_assert_cmpint (data->rs_counter, ==, 1);
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_DHCP_LEVEL |
			                          NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES |
			                          NM_RDISC_CONFIG_DNS_SERVERS |
			                          NM_RDISC_CONFIG_DNS_DOMAINS |
			                          NM_RDISC_CONFIG_HOP_LIMIT |
			                          NM_RDISC_CONFIG_MTU);
		match_gateway (rdisc->gateways, 0, "fe80::1", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_route (rdisc->routes, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
		match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::1", data->timestamp1, 10);
		match_dns_domain (rdisc->dns_domains, 0, "foobar.com", data->timestamp1, 10);
	} else if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES |
			                          NM_RDISC_CONFIG_DNS_SERVERS |
			                          NM_RDISC_CONFIG_DNS_DOMAINS);

		g_assert_cmpint (rdisc->gateways->len, ==, 1);
		match_gateway (rdisc->gateways, 0, "fe80::2", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		g_assert_cmpint (rdisc->addresses->len, ==, 1);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::2", data->timestamp1, 10, 10);
		g_assert_cmpint (rdisc->routes->len, ==, 1);
		match_route (rdisc->routes, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1, 10, 10);
		g_assert_cmpint (rdisc->dns_servers->len, ==, 1);
		match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::2", data->timestamp1, 10);
		g_assert_cmpint (rdisc->dns_domains->len, ==, 1);
		match_dns_domain (rdisc->dns_domains, 0, "foobar2.com", data->timestamp1, 10);

		g_assert (nm_fake_rdisc_done (NM_FAKE_RDISC (rdisc)));
		g_main_loop_quit (data->loop);
	} else
		g_assert_not_reached ();

	data->counter++;
}

static void
test_everything (void)
{
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 10);

	/* expire everything from the first RA in the second */
	id = nm_fake_rdisc_add_ra (rdisc, 2, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 0, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 0, 0);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 0, 0);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 0);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 0);

	/* and add some new stuff */
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::2", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::2", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::2", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar2.com", now, 10);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_everything_changed),
	                  &data);
	g_signal_connect (rdisc,
	                  NM_FAKE_RDISC_RS_SENT,
	                  G_CALLBACK (test_everything_rs_sent),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 2);
	g_assert_cmpint (data.rs_counter, ==, 1);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	nm_logging_setup ("debug", "ip6", NULL, NULL);
	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);

	nm_fake_platform_setup ();

	g_test_add_func ("/rdisc/simple", test_simple);
	g_test_add_func ("/rdisc/everything-changed", test_everything);

	return g_test_run ();
}
