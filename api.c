/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "p0f.h"
#include "api.h"
#include "process.h"
#include "readfp.h"

/* Process API queries. */

void handle_query(struct p0f_api_query_v2* q, struct p0f_api_response* r) {

  memset(r, 0, sizeof(struct p0f_api_response));

  r->magic = P0F_RESP_MAGIC;

  if (q->magic == P0F_QUERY_MAGIC) {

      handle_query_v1(q, r);

  }

  else if (q->magic == P0F_QUERY_MAGIC_V2) {

      handle_query_v2(q, r);

  }

  else {

    WARN("Query with bad magic (0x%x).", q->magic);

    r->status = P0F_STATUS_BADQUERY;

  }

}

void handle_query_v1(struct p0f_api_query* q, struct p0f_api_response* r) {

  struct host_data* h;

  switch (q->addr_type) {

    case P0F_ADDR_IPV4:
    case P0F_ADDR_IPV6:
      h = lookup_host(q->addr, q->addr_type);
      break;

    default:

      WARN("Query with unknown address type %u.\n", q->addr_type);
      r->status = P0F_STATUS_BADQUERY;
      return;

  }

  if (!h) {
    r->status = P0F_STATUS_NOMATCH;
    return;
  }

  r->status     = P0F_STATUS_OK;
  r->first_seen = h->first_seen;
  r->last_seen  = h->last_seen;
  r->total_conn = h->total_conn;

  if (h->last_name_id != -1) {

    strncpy((char*)r->os_name, (char*)fp_os_names[h->last_name_id],
            P0F_STR_MAX + 1);

    if (h->last_flavor)
       strncpy((char*)r->os_flavor, (char*)h->last_flavor, P0F_STR_MAX + 1);

  }

  if (h->http_name_id != -1) {

    strncpy((char*)r->http_name, (char*)fp_os_names[h->http_name_id],
            P0F_STR_MAX + 1);

    if (h->http_flavor)
      strncpy((char*)r->http_flavor, (char*)h->http_flavor, P0F_STR_MAX + 1);

  }

  if (h->link_type)
    strncpy((char*)r->link_type, (char*)h->link_type, P0F_STR_MAX + 1);

  if (h->language)
    strncpy((char*)r->language, (char*)h->language, P0F_STR_MAX + 1);

  r->bad_sw      = h->bad_sw;
  r->last_nat    = h->last_nat;
  r->last_chg    = h->last_chg;
  r->up_mod_days = h->up_mod_days;
  r->distance    = h->distance;
  r->os_match_q  = h->last_quality;

  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;

}

void handle_query_v2(struct p0f_api_query_v2* q, struct p0f_api_response* r) {

  struct packet_flow* f;
  struct host_data* h;
  u8 to_srv;

  struct packet_data pk;

  pk.ip_ver = q->addr_type;
  memcpy(pk.src, q->addr_src, 16);
  memcpy(pk.dst, q->addr_dst, 16);

  pk.sport = q->src_port;
  pk.dport = q->dst_port;

  switch (q->addr_type) {

    case P0F_ADDR_IPV4:
    case P0F_ADDR_IPV6:
      f = lookup_flow(&pk, &to_srv);
      break;

    default:

      WARN("Query with unknown address type %u.\n", q->addr_type);
      r->status = P0F_STATUS_BADQUERY;
      return;

  }

  if (!f) {
    r->status = P0F_STATUS_NOMATCH;
    return;
  }

  h = (to_srv) ? f->client : f->server;

  r->status     = P0F_STATUS_OK;
  r->first_seen = h->first_seen;
  r->last_seen  = h->last_seen;
  r->total_conn = h->total_conn;

  if (h->last_name_id != -1) {

    strncpy((char*)r->os_name, (char*)fp_os_names[h->last_name_id],
            P0F_STR_MAX + 1);

    if (h->last_flavor)
       strncpy((char*)r->os_flavor, (char*)h->last_flavor, P0F_STR_MAX + 1);

  }

  if (h->http_name_id != -1) {

    strncpy((char*)r->http_name, (char*)fp_os_names[h->http_name_id],
            P0F_STR_MAX + 1);

    if (h->http_flavor)
      strncpy((char*)r->http_flavor, (char*)h->http_flavor, P0F_STR_MAX + 1);

  }

  if (h->link_type)
    strncpy((char*)r->link_type, (char*)h->link_type, P0F_STR_MAX + 1);

  if (h->language)
    strncpy((char*)r->language, (char*)h->language, P0F_STR_MAX + 1);

  r->bad_sw      = h->bad_sw;
  r->last_nat    = h->last_nat;
  r->last_chg    = h->last_chg;
  r->up_mod_days = h->up_mod_days;
  r->distance    = h->distance;
  r->os_match_q  = h->last_quality;

  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;

}
