/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/ri_trace_hook.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define RI_TRACE_HEADER_MAX 512
#define RI_TRACE_ACK_MAX 16
#define RI_TRACE_DEFAULT_TIMEOUT_MS 100

static int trace_fd = -1;

static void close_trace_fd(void)
{
	if (trace_fd >= 0)
		close(trace_fd);
	trace_fd = -1;
}

void ri_trace_hook_close(void)
{
	close_trace_fd();
}

static int configured_timeout_ms(void)
{
	const char *raw = getenv("RI_TRACE_ACK_TIMEOUT_MS");
	if (!raw || !raw[0])
		return RI_TRACE_DEFAULT_TIMEOUT_MS;
	char *end = NULL;
	long parsed = strtol(raw, &end, 10);
	if (!end || *end || parsed < 1 || parsed > 5000)
		return -1;
	return (int)parsed;
}

static int connect_trace(void)
{
	if (trace_fd >= 0)
		return 0;
	const char *path = getenv("RI_KNOT_TRACE_HOOK_SOCKET");
	const int timeout_ms = configured_timeout_ms();
	if (!path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)
	    || timeout_ms < 0)
		return -1;

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	struct timeval timeout = {
		.tv_sec = timeout_ms / 1000,
		.tv_usec = (timeout_ms % 1000) * 1000
	};
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0
	    || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
		close(fd);
		return -1;
	}
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	memcpy(address.sun_path, path, strlen(path) + 1);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		close(fd);
		return -1;
	}
	trace_fd = fd;
	return 0;
}

static const char *dnssec_status(const struct kr_request *request)
{
	if (kr_rank_test(request->rank, KR_RANK_BOGUS))
		return "bogus";
	if (kr_rank_test(request->rank, KR_RANK_SECURE))
		return "secure";
	if (kr_rank_test(request->rank, KR_RANK_INSECURE))
		return "insecure";
	return "indeterminate";
}

static const char *transport_name(const struct kr_transport *transport)
{
	if (!transport)
		return "none";
	switch (transport->protocol) {
	case KR_TRANSPORT_UDP:
		return "udp";
	case KR_TRANSPORT_TCP:
		return "tcp";
	case KR_TRANSPORT_TLS:
		return "tls";
	default:
		return "none";
	}
}

static int endpoint_text(const struct kr_transport *transport,
			 char *address, size_t address_size, uint16_t *port)
{
	if (!transport) {
		memcpy(address, "-", 2);
		*port = 0;
		return 0;
	}
	const struct sockaddr *socket_address = &transport->address.ip;
	const void *source = NULL;
	if (socket_address->sa_family == AF_INET) {
		const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)socket_address;
		source = &ipv4->sin_addr;
		*port = ntohs(ipv4->sin_port);
	} else if (socket_address->sa_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)socket_address;
		source = &ipv6->sin6_addr;
		*port = ntohs(ipv6->sin6_port);
	} else {
		return -1;
	}
	return inet_ntop(socket_address->sa_family, source, address, address_size)
		? 0 : -1;
}

static int write_all(int fd, const uint8_t *buffer, size_t length)
{
	while (length > 0) {
		ssize_t written = send(fd, buffer, length, MSG_NOSIGNAL);
		if (written <= 0)
			return -1;
		buffer += written;
		length -= (size_t)written;
	}
	return 0;
}

static int read_ack(int fd)
{
	char ack[RI_TRACE_ACK_MAX] = { 0 };
	size_t used = 0;
	while (used + 1 < sizeof(ack)) {
		ssize_t received = recv(fd, ack + used, 1, 0);
		if (received != 1)
			return -1;
		if (ack[used++] == '\n')
			break;
	}
	return used == 3 && memcmp(ack, "OK\n", 3) == 0 ? 0 : -1;
}

static int emit_hook(const char *kind, const struct kr_request *request,
		     const struct kr_transport *transport,
		     const knot_pkt_t *packet, const char *reason)
{
	if (!request || !kind || !reason || strchr(reason, ' ') || strchr(reason, '\n')) {
		fprintf(stderr, "[ri-trace] rejected invalid %s hook fields\n",
			kind ? kind : "unknown");
		return -1;
	}
	const size_t wire_length = packet ? packet->size : 0;
	if (wire_length > UINT16_MAX)
		return -1;
	char address[INET6_ADDRSTRLEN] = "-";
	uint16_t port = 0;
	if (endpoint_text(transport, address, sizeof(address), &port) != 0) {
		fprintf(stderr, "[ri-trace] %s hook has no valid transport endpoint\n", kind);
		return -1;
	}
	char header[RI_TRACE_HEADER_MAX];
	int header_length = snprintf(
		header, sizeof(header), "RIK1 %s %ld %u %s %s %u %s %s %zu -\n",
		kind, (long)getpid(), request->uid, transport_name(transport), address,
		(unsigned)port, dnssec_status(request), reason, wire_length);
	if (header_length <= 0 || (size_t)header_length >= sizeof(header)) {
		fprintf(stderr, "[ri-trace] %s hook header exceeds its bound\n", kind);
		return -1;
	}
	if (connect_trace() != 0) {
		fprintf(stderr, "[ri-trace] %s hook cannot connect to Trace Producer\n", kind);
		return -1;
	}
	if (write_all(trace_fd, (const uint8_t *)header, (size_t)header_length) != 0
	    || (wire_length > 0
		&& write_all(trace_fd, packet->wire, wire_length) != 0)) {
		fprintf(stderr, "[ri-trace] %s hook cannot write to Trace Producer\n", kind);
		close_trace_fd();
		return -1;
	}
	if (read_ack(trace_fd) != 0) {
		fprintf(stderr, "[ri-trace] %s hook did not receive a durable ACK\n", kind);
		close_trace_fd();
		return -1;
	}
	return 0;
}

int ri_trace_hook_begin(const struct kr_request *request, const knot_pkt_t *packet)
{
	return emit_hook("BEGIN", request, NULL, packet, "accepted");
}

int ri_trace_hook_send(const struct kr_request *request,
		       const struct kr_transport *transport,
		       const knot_pkt_t *packet)
{
	return emit_hook("SEND", request, transport, packet, "send");
}

int ri_trace_hook_response(const struct kr_request *request,
			   const struct kr_transport *transport,
			   const knot_pkt_t *packet)
{
	return emit_hook("RESPONSE", request, transport, packet, "received");
}

int ri_trace_hook_failure(const struct kr_request *request,
			  const struct kr_transport *transport,
			  const char *reason)
{
	return emit_hook("FAILURE", request, transport, NULL, reason);
}

int ri_trace_hook_finish(const struct kr_request *request,
			 const knot_pkt_t *packet, bool success)
{
	return emit_hook("FINISH", request, NULL, packet,
			 success ? "success" : "resolver-failed");
}
