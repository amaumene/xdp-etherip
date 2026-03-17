#include "xdp_prog.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tunnel_config);
} tunnel_config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, DBG_MAX);
  __type(key, __u32);
  __type(value, __u64);
} debug_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u32);
} redirect_devmap SEC(".maps");

static __always_inline void dbg_inc(__u32 idx) {
  __u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
  if (val) (*val)++;
}

static __always_inline int skip_ext_headers(void *data_end, void **pos,
                                            __u8 *nexthdr) {
#pragma unroll
  for (int i = 0; i < MAX_EXT_HEADERS; i++) {
    if (*nexthdr != 0 && *nexthdr != 43 && *nexthdr != 44 && *nexthdr != 60)
      return 0;
    __u8 cur = *nexthdr;
    struct ipv6_ext_hdr *ext = *pos;
    if ((void *)(ext + 1) > data_end) return -1;
    *nexthdr = ext->nexthdr;
    if (cur == 44)
      *pos += 8;
    else
      *pos += (ext->hdrlen + 1) * 8;
    if (*pos > data_end) return -1;
  }
  return 0;
}

static __always_inline void update_checksum(__u16 *csum, __u16 old_val,
                                            __u16 new_val) {
  __u32 new_csum_value;
  __u32 new_csum_comp;
  __u32 undo;

  undo = ~((__u32)*csum) + ~((__u32)old_val);
  new_csum_value = undo + (undo < ~((__u32)old_val)) + (__u32)new_val;
  new_csum_comp = new_csum_value + (new_csum_value < ((__u32)new_val));
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  *csum = (__u16)~new_csum_comp;
}

static __always_inline int update_tcp_mss(void *data, void *data_end,
                                          int new_mss_int) {
  struct tcphdr *tcp = data;
  if (data + sizeof(struct tcphdr) > data_end) return 1;
  if (tcp->syn != 1) return 0;

  __u8 doff = tcp->doff;
  if (doff < 5) return 0;
  if (data + (__u32)doff * 4 > data_end) return 1;

  int remaining = doff * 4 - (int)sizeof(struct tcphdr);
  void *opt_ptr = data + sizeof(struct tcphdr);

  for (int i = 0; i < MAX_TCP_OPT_ITERATIONS; i++) {
    if (remaining < 1 || opt_ptr + 1 > data_end) break;
    __u8 kind = *(__u8 *)opt_ptr;
    if (kind == 0) break;
    if (kind == 1) { opt_ptr += 1; remaining -= 1; continue; }
    if (remaining < 2 || opt_ptr + 2 > data_end) break;
    __u8 len = *(__u8 *)(opt_ptr + 1);
    if (len < 2 || len > remaining || opt_ptr + len > data_end) break;
    if (kind == 2 && len == 4) {
      asm volatile("" : "+r"(opt_ptr));
      if (opt_ptr + 4 > data_end) return 1;
      __u16 *mss_val = (__u16 *)(opt_ptr + 2);
      __u16 old_mss = *mss_val;
      if (bpf_ntohs(old_mss) > new_mss_int) {
        __u16 new_mss = bpf_htons(new_mss_int);
        __builtin_memcpy(mss_val, &new_mss, sizeof(__u16));
        update_checksum(&tcp->check, old_mss, new_mss);
      }
      return 0;
    }
    opt_ptr += len;
    remaining -= len;
  }
  return 0;
}

static __always_inline __u32 inner_flow_hash(void *data, void *data_end) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return 0;
  __u32 h = 0;
#pragma unroll
  for (int i = 0; i < 6; i++)
    h = h * 31 + eth->h_dest[i];
#pragma unroll
  for (int i = 0; i < 6; i++)
    h = h * 31 + eth->h_source[i];
  h = h * 31 + bpf_ntohs(eth->h_proto);

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) <= data_end) {
      h = h * 31 + ip->saddr;
      h = h * 31 + ip->daddr;
    }
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) <= data_end) {
#pragma unroll
      for (int i = 0; i < 16; i++)
        h = h * 31 + ip6->saddr.s6_addr[i];
#pragma unroll
      for (int i = 0; i < 16; i++)
        h = h * 31 + ip6->daddr.s6_addr[i];
    }
  }

  return h & 0xFFFFF;
}

static __always_inline struct tunnel_config *get_tunnel_config(void) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&tunnel_config_map, &key);
}

static __always_inline int build_outer_headers(void *data, void *data_end,
                                               struct tunnel_config *cfg,
                                               __u32 flow_hash) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return -1;
  eth->h_proto = bpf_htons(ETH_P_IPV6);

  struct ipv6hdr *ip6 = (void *)(eth + 1);
  if ((void *)(ip6 + 1) > data_end) return -1;
  ip6->version = 6;
  ip6->priority = 0;
  ip6->flow_lbl[0] = (flow_hash >> 16) & 0x0F;
  ip6->flow_lbl[1] = (flow_hash >> 8) & 0xFF;
  ip6->flow_lbl[2] = flow_hash & 0xFF;
  ip6->nexthdr = ETHERIP_PROTO;
  ip6->hop_limit = HOP_LIMIT_DEFAULT;
  __builtin_memcpy(ip6->saddr.s6_addr, cfg->src_addr, sizeof(cfg->src_addr));
  __builtin_memcpy(ip6->daddr.s6_addr, cfg->dst_addr, sizeof(cfg->dst_addr));

  struct etherip_hdr *eip = (void *)(ip6 + 1);
  if ((void *)(eip + 1) > data_end) return -1;
  eip->etherip_ver = ETHERIP_VERSION;
  eip->etherip_pad = 0x00;

  ip6->payload_len = bpf_htons(data_end - (void *)eip);
  return 0;
}

static __always_inline int clamp_inner_tcp_mss(void *data, void *data_end,
                                                struct tunnel_config *cfg) {
  struct ethhdr *inner_eth = data;
  if ((void *)(inner_eth + 1) > data_end) return -1;

  if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(inner_eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;
    if (ip->protocol == 6) {
      __u8 ihl = ip->ihl;
      if (ihl < 5) return -1;
      void *tcp = (void *)ip + (__u32)ihl * 4;
      return update_tcp_mss(tcp, data_end, cfg->mss_clamp_ipv4);
    }
  }

  if (inner_eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(inner_eth + 1);
    if ((void *)(ip6 + 1) > data_end) return -1;
    __u8 nexthdr = ip6->nexthdr;
    void *pos = (void *)(ip6 + 1);
    if (skip_ext_headers(data_end, &pos, &nexthdr)) return -1;
    if (nexthdr == 6) {
      return update_tcp_mss(pos, data_end, cfg->mss_clamp_ipv6);
    }
  }

  return 0;
}

static __always_inline int addr_equal(__u8 *a, __u8 *b) {
  return __builtin_memcmp(a, b, 16) == 0;
}

static __always_inline int handle_decap(struct xdp_md *ctx,
                                        struct tunnel_config *cfg) {
  dbg_inc(DBG_DECAP_ENTER);
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_ABORTED;
  if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
    dbg_inc(DBG_DECAP_NOT_IPV6);
    return XDP_PASS;
  }

  struct ipv6hdr *ip6 = (void *)(eth + 1);
  if ((void *)(ip6 + 1) > data_end) return XDP_ABORTED;

  __u8 nexthdr = ip6->nexthdr;
  void *pos = (void *)(ip6 + 1);
  if (skip_ext_headers(data_end, &pos, &nexthdr)) return XDP_ABORTED;

  if (nexthdr != ETHERIP_PROTO) {
    dbg_inc(DBG_DECAP_NOT_ETHERIP);
    return XDP_PASS;
  }

  if (addr_equal(ip6->saddr.s6_addr, cfg->src_addr)) {
    dbg_inc(DBG_DECAP_OWN_PKT);
    return XDP_PASS;
  }

  struct etherip_hdr *eip = pos;
  if ((void *)(eip + 1) > data_end) return XDP_ABORTED;
  if (eip->etherip_ver != ETHERIP_VERSION || eip->etherip_pad != 0x00) {
    dbg_inc(DBG_DECAP_BAD_HEADER);
    return XDP_PASS;
  }

  if ((void *)(eip + 1) + sizeof(struct ethhdr) > data_end)
    return XDP_ABORTED;

  int strip_len = (int)((void *)(eip + 1) - data);
  if (bpf_xdp_adjust_head(ctx, strip_len)) return XDP_ABORTED;

  data = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;
  struct ethhdr *inner_eth = data;
  if ((void *)(inner_eth + 1) > data_end) return XDP_ABORTED;
  __builtin_memcpy(inner_eth->h_dest, cfg->tunnel_mac, 6);

  dbg_inc(DBG_DECAP_REDIRECT);
  return bpf_redirect_map(&redirect_devmap, DEVMAP_TUNNEL, 0);
}

static __always_inline int handle_encap(struct xdp_md *ctx,
                                        struct tunnel_config *cfg) {
  dbg_inc(DBG_ENCAP_ENTER);
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *orig_eth = data;
  if ((void *)(orig_eth + 1) > data_end) return XDP_ABORTED;

  __u32 flow_hash = inner_flow_hash(data, data_end);

  int outer_len = (int)(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
                        sizeof(struct etherip_hdr));
  if (bpf_xdp_adjust_head(ctx, 0 - outer_len)) {
    dbg_inc(DBG_ENCAP_ADJUST_FAIL);
    return XDP_ABORTED;
  }

  data = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;

  if (build_outer_headers(data, data_end, cfg, flow_hash)) {
    dbg_inc(DBG_ENCAP_BUILD_FAIL);
    return XDP_ABORTED;
  }

  void *inner = data + outer_len;
  if (clamp_inner_tcp_mss(inner, data_end, cfg)) {
    dbg_inc(DBG_ENCAP_MSS_FAIL);
    return XDP_ABORTED;
  }

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    dbg_inc(DBG_ENCAP_BOUNDS_FAIL);
    return XDP_ABORTED;
  }

  __builtin_memcpy(eth->h_dest, cfg->dst_mac, 6);
  __builtin_memcpy(eth->h_source, cfg->external_mac, 6);

  dbg_inc(DBG_ENCAP_REDIRECT);
  return bpf_redirect_map(&redirect_devmap, DEVMAP_EXTERNAL, 0);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  dbg_inc(DBG_MAIN_ENTER);
  struct tunnel_config *cfg = get_tunnel_config();
  if (!cfg) {
    dbg_inc(DBG_MAIN_NO_CFG);
    return XDP_ABORTED;
  }

  if (ctx->ingress_ifindex == cfg->internal_ifindex)
    return handle_encap(ctx, cfg);

  return handle_decap(ctx, cfg);
}

char __license[] SEC("license") = "Dual MIT/GPL";
