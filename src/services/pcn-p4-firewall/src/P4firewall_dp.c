/*
 * Copyright 2020 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>

struct ethernet {
    u64 dstAddr : 48; /* bit<48> */
    u64 srcAddr : 48; /* bit<48> */
    u16 etherType; /* bit<16> */
} __attribute__((packed));

struct ipv4 {
    u8 version : 4; /* bit<4> */
    u8 ihl : 4; /* bit<4> */
    u8 diffserv; /* bit<8> */
    u16 totalLen; /* bit<16> */
    u16 identification; /* bit<16> */
    u8 flags : 3; /* bit<3> */
    u16 fragOffset : 13; /* bit<13> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdrChecksum; /* bit<16> */
    u32 srcAddr; /* bit<32> */
    u32 dstAddr; /* bit<32> */
} __attribute__((packed));

struct tcp {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u32 seqNo; /* bit<32> */
    u32 ackNo; /* bit<32> */
    u8 dataOffset : 4; /* bit<4> */
    u8 res : 4; /* bit<4> */
    u8 flags; /* bit<8> */
    u16 window; /* bit<16> */
    u16 checksum; /* bit<16> */
    u16 urgentPtr; /* bit<16> */
} __attribute__((packed));

struct cp_k {
    u32 ingress_port; /* bit<32> */
    u32 egress_spec; /* bit<32> */
} __attribute__((packed));

struct ipv4_fw_v {
    u64 dstAddr : 48; /* bit<48> */
    u32 port; /* bit<32> */
} __attribute__((packed));

struct ipv4_fw_k {
    u32 netmask; /* bit<32> */
    u32 address; /* bit<32> */
} __attribute__((packed));

struct headers {
    struct ethernet *ethernet; /* ethernet */
    struct ipv4 *ipv4; /* ipv4 */
    struct tcp *tcp; /* tcp */
} __attribute__((packed));

struct st_k {
    u32 srcIp; /* bit<32> */
    u32 dstIp; /* bit<32> */
    u32 srcPort; /* bit<32> */
    u32 dstPort; /* bit<32> */
} __attribute__((packed));

BPF_TABLE("hash", struct cp_k, u8, check_ports, 1024);
BPF_F_TABLE("lpm_trie", struct ipv4_fw_k, struct ipv4_fw_v, ipv4_lpm, 1024, BPF_F_NO_PREALLOC);
BPF_TABLE("hash", struct st_k, u8, sessions, 65536);

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md){
  struct headers hdr = {};
  void* polycube_packetStart = ((void*)(long)ctx->data);
  void* polycube_packetEnd = ((void*)(long)ctx->data_end);

  goto start;
  start: {
  /* extract(hdr.ethernet)*/
  hdr.ethernet = polycube_packetStart;
  if (polycube_packetStart + sizeof(*(hdr.ethernet)) > polycube_packetEnd) {
    goto reject;
  }
  goto accept;
}

  reject: { return RX_ERROR; }

  accept:
  {
    u8 hit;
    u8 internalNetwork_0;
    u8 miss_0;
    struct cp_k check_ports_key_0;
    struct ipv4_fw_v forward_value_0;
    struct st_k sessions_key_0;
    u8 isSessionSet_0;
    struct ipv4_fw_k forward_key_0;
    u32 new_ttl_0;
    u32 l3sum_0;
    u32 old_ttl_0;
    u16 tmp;
    {
      tmp = /* htons(0x800)*/
              htons(0x800);
      if (hdr.ethernet->etherType != tmp)
        /* pcn_pkt_controller(ctx, md, 1)*/
        return pcn_pkt_controller(ctx, md, 1);
      hdr.ipv4 = polycube_packetStart + sizeof(*(hdr.ethernet));
      if (polycube_packetStart + sizeof(*(hdr.ethernet)) + sizeof(*(hdr.ipv4)) > polycube_packetEnd) {
        goto reject;
      }

      miss_0 = false;
      forward_key_0.address = hdr.ipv4->dstAddr;
      forward_key_0.netmask = 32;
      /* ipv4_lpm_0.apply()*/
      {
        /* construct key */
        struct ipv4_fw_k key;
        key = forward_key_0;
        /* value */
        struct ipv4_fw_v *value = NULL;
        /* perform lookup */
        value = ipv4_lpm.lookup(&key);
        /* run action */
        if (value != NULL)
        {
          forward_value_0 = (*value);
        }
        else
        {
          miss_0 = true;
        }
      };
      if (miss_0)
        /* pcn_pkt_controller(ctx, md, 1)*/
        return pcn_pkt_controller(ctx, md, 1);
      hdr.ethernet->srcAddr = hdr.ethernet->dstAddr;
      hdr.ethernet->dstAddr = forward_value_0.dstAddr;
      internalNetwork_0 = 0;
      miss_0 = false;
      check_ports_key_0.ingress_port = ((u32)md->in_port);
      check_ports_key_0.egress_spec = forward_value_0.port;
      /* check_ports_0.apply()*/
      {
        /* construct key */
        struct cp_k key;
        key = check_ports_key_0;
        /* value */
        u8 *value = NULL;
        /* perform lookup */
        value = check_ports.lookup(&key);
        /* run action */
        if (value != NULL)
        {
          internalNetwork_0 = (*value);
        }
        else
        {
          miss_0 = true;
        }
      };
      if (((!miss_0) && hdr.ipv4->protocol == 6)) {
        hdr.tcp = polycube_packetStart + sizeof(*(hdr.ethernet)) + sizeof(*(hdr.ipv4));
        if (polycube_packetStart + sizeof(*(hdr.ethernet)) + sizeof(*(hdr.ipv4)) + sizeof(*(hdr.tcp)) > polycube_packetEnd) {
          goto reject;
        }

        if (internalNetwork_0 == 0) {
          sessions_key_0.srcIp = hdr.ipv4->srcAddr;
          sessions_key_0.dstIp = hdr.ipv4->dstAddr;
          sessions_key_0.srcPort = ((u32) hdr.tcp->srcPort);
          sessions_key_0.dstPort = ((u32) hdr.tcp->dstPort);
          isSessionSet_0 = 1;
          if ((hdr.tcp->flags & 0x2) != 0)
            /* TABLE_UPDATE(""sessions"", sessions_key_0, isSessionSet_0)*/
            sessions.update(&sessions_key_0, &isSessionSet_0);
        } else {
          sessions_key_0.srcIp = hdr.ipv4->dstAddr;
          sessions_key_0.dstIp = hdr.ipv4->srcAddr;
          sessions_key_0.srcPort = ((u32) hdr.tcp->dstPort);
          sessions_key_0.dstPort = ((u32) hdr.tcp->srcPort);
          isSessionSet_0 = 0;
          /* sessions_0.apply()*/
          {
            /* construct key */
            struct st_k key;
            key = sessions_key_0;
            /* value */
            u8 *value = NULL;
            /* perform lookup */
            value = sessions.lookup(&key);
            /* run action */
            if (value != NULL) {
              isSessionSet_0 = (*value);
            } else {
              miss_0 = true;
            }
          };
          if (isSessionSet_0 != 1)
            /* pcn_pkt_drop(ctx, md)*/
            return RX_DROP;;
        }
      }
      l3sum_0 = 0;
      /* SUBTRACTION(new_ttl_0, ((u32)hdr.ipv4->ttl), 1)*/
      new_ttl_0 = ((u32)hdr.ipv4->ttl) - 1;
      old_ttl_0 = ((u32)hdr.ipv4->ttl);
      l3sum_0 = /* bpf_csum_diff(old_ttl_0, 4, new_ttl_0, 4, 0)*/
              bpf_csum_diff(&old_ttl_0, 4, &new_ttl_0, 4, 0);
      hdr.ipv4->ttl = ((u8)new_ttl_0);
      /* bpf_l3_csum_replace(ctx, 24, 0, l3sum_0, 0)*/
      bpf_l3_csum_replace(ctx, 24, 0, l3sum_0, 0);
      /* pcn_pkt_redirect(ctx, md, ((u16)forward_value_0.port))*/
      return pcn_pkt_redirect(ctx, md, ((u16)forward_value_0.port));
    }
  }
  polycube_end: return RX_DROP;
}
