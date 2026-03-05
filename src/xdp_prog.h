#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

#define MSS_CLAMP_IPV4 1404
#define MSS_CLAMP_IPV6 1384
#define ETHERIP_PROTO 97
#define HOP_LIMIT_DEFAULT 64
#define ETHERIP_VERSION 0x30
#define DEVMAP_EXTERNAL 0
#define DEVMAP_TUNNEL 1

// tcp options
struct tcpopt {
  __u8 kind;
  __u8 len;
};

// EtherIP header
struct etherip_hdr {
  __u8 etherip_ver;
  __u8 etherip_pad;
};

struct tunnel_config {
  __u8 src_addr[16];
  __u8 dst_addr[16];
  __u32 internal_ifindex;
  __u32 external_ifindex;
  __u32 tunnel_ifindex;
  __u8 tunnel_mac[6];
  __u8 internal_mac[6];
  __u8 external_mac[6];
  __u8 dst_mac[6];
};

enum debug_counter {
  DBG_ENCAP_ENTER = 0,
  DBG_ENCAP_ADJUST_FAIL,
  DBG_ENCAP_BUILD_FAIL,
  DBG_ENCAP_MSS_FAIL,
  DBG_ENCAP_BOUNDS_FAIL,
  DBG_ENCAP_REDIRECT,
  DBG_DECAP_ENTER,
  DBG_DECAP_NOT_IPV6,
  DBG_DECAP_NOT_ETHERIP,
  DBG_DECAP_OWN_PKT,
  DBG_DECAP_BAD_HEADER,
  DBG_DECAP_REDIRECT,
  DBG_MAIN_ENTER,
  DBG_MAIN_NO_CFG,
  DBG_MAX,
};

#endif  // XDP_PROG_H
