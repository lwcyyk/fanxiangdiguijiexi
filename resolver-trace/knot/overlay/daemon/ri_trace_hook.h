/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>

#include <libknot/packet/pkt.h>

#include "lib/resolve.h"
#include "lib/selection.h"

int ri_trace_hook_begin(const struct kr_request *request, const knot_pkt_t *packet);
int ri_trace_hook_send(const struct kr_request *request,
		       const struct kr_transport *transport,
		       const knot_pkt_t *packet);
int ri_trace_hook_response(const struct kr_request *request,
			   const struct kr_transport *transport,
			   const knot_pkt_t *packet);
int ri_trace_hook_failure(const struct kr_request *request,
			  const struct kr_transport *transport,
			  const char *reason);
int ri_trace_hook_finish(const struct kr_request *request,
			 const knot_pkt_t *packet, bool success);
void ri_trace_hook_close(void);
