Writing the eBPF datapath
^^^^^^^^^^^^^^^^^^^^^^^^^

`eBPF <http://cilium.readthedocs.io/en/latest/bpf/>`_ is an extension of the traditional Berkeley Packet Filter.
The Polycube architecture leverages the software abstraction provided by `BCC <https://github.com/iovisor/bcc/>`_, which is further extended in this project particular with respect to eBPF features that are useful for networking services.
In order to get more information about how to use the maps in BCC please read the `BCC reference guide <https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md>`_, additionally there is a list of the `available eBPF helpers <https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md>`_.

Polycube architecture adds a wrapper around the user's code, this wrapper calls the `handle_rx` function with the following parameters:

1. **ctx**: Packet to be processed
2. **md**: packet's metadata:

 - **in_port**: integer that identifies the ingress port of the packet.

``polycube`` provides a set of functions to handle the packets, the return value of the `handle_rx` function should be the result of calling one of these functions.

- **pcn_pkt_redirect(struct __sk_buff *skb, struct pkt_metadata *md, u16 port);**: sends the packet through an the ``ifc`` port. [Example](services/pcn-helloworld/src/Helloworld_dp.h#L86)

- **pcn_pkt_drop(struct __sk_buff *skb, struct pkt_metadata *md);**: drops the packet. It is the same that just returning `RX_DROP`. [Example](services/pcn-helloworld/src/Helloworld_dp.h#L78)

- **pcn_pkt_controller(struct __sk_buff *skb, struct pkt_metadata *md, u16 reason)**: sends the packet to the control path controller. Reason can be used to indicate why the packet is being sent to the custom code running in the control path. If there is not any reason `RX_CONTROLLER` could be directly returned. [Example](services/pcn-helloworld/src/Helloworld_dp.h#L82)

- **pcn_pkt_controller_with_metadata(struct __sk_buff *skb, struct pkt_metadata *md, u16 reason, u32 metadata[3])**: Sends the packet to the custom code running in the control path. In addition to the reason the user can also send some additional medatada.

- **pcn_pkt_redirect_ns(struct __sk_buff *skb, struct pkt_metadata *md, u16 port)**: (it is only available for shadow services) sends the packet to the namespace as if it came from the port indicated as parameter

Checksum calculation
********************

The L3 (IP) and L4 (TCP, UDP) checksums has to be updated when fields in the packets are changed.
``polycube`` provides a set of wrappers of the eBPF helpers to do it:

- **pcn_csum_diff()**: wrapper of `BPF_FUNC_csum_diff <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7d672345ed295b1356a5d9f7111da1d1d7d65867>`_

    Note: For XDP cubes and kernels version prior to 4.16 this function supports only 4 bytes arguments.

- **pcn_l3_csum_replace()**: wrapper of `BPF_FUNC_l3_csum_replace <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=91bc4822c3d61b9bb7ef66d3b77948a4f9177954>`_

- **pcn_l4_csum_replace()**: wrapper of `BPF_FUNC_l4_csum_replace <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=91bc4822c3d61b9bb7ef66d3b77948a4f9177954>`_

Services as :scm_web:`nat <src/services/pcn-nat/src/Nat_dp.c>` and :scm_web:`nat <src/services/pcn-loadbalancer-rp/src/Lbrp_dp.c>` show how to use these functions.

Vlan Support
************

The vlan handling in TC and XDP eBPF programs is a little bit different, so polycube includes a set of helpers to uniform this accross.

- bool pcn_is_vlan_present(struct CTXTYPE* pkt)

- int pcn_get_vlan_id(struct CTXTYPE* pkt, uint16_t* vlan_id, uint16_t* eth_proto);

- uint8_t pcn_vlan_pop_tag(struct CTXTYPE* pkt);

- uint8_t pcn_vlan_push_tag(struct CTXTYPE* pkt, u16 eth_proto, u32 vlan_id);


Known limitations:
******************
- It is not possible to send a packet through multiple ports, then multicast, broadcast of any similar functionality has to be implemented in the control path.


TODO:
*****

- Document support for multiple eBPF programs


Debugging the data plane
***************************************
See how to debug by :ref:`logging in the dataplane <logging-data-plane>`.


Experimental: Write Polycube service data plane in P4
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The purpose of this section is to offer a way to create eBPF injectable code
from a P4 implementation, following the polycube model. Examples of p4 service
implementation are present in the folder of simplebridge and router.

**N.B.**: The compiler is not bug free, but little misbehavior are solvable with
small code adaption (e.g. if an assignment goes missing in the translation, do
it as early as possible, even if used later or it could not be used at all).

Installation
************

**Option 1: git repository**

1. Clone the repository, switch to ``polycube_translation`` branch and update
submodules:

::

  git clone https://github.com/richiMarchi/p4c.git
  git checkout polycube_translation
  git submodule update --init --recursive

2. Install dependencies:

::

  sudo apt-get install cmake g++ git automake libtool libgc-dev bison flex \
  libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev libboost-graph-dev \
  llvm pkg-config python python-scapy python-ipaddr python-ply python3-pip \
  tcpdump libprotobuf-dev

  pip3 install scapy ply

3. Build the compiler enabling polycube backend only:

::

  mkdir build
  cd build
  cmake .. -DENABLE_BMV2=OFF -DENABLE_EBPF=OFF -DENABLE_P4C_GRAPHS=OFF \
  -DENABLE_P4TEST=OFF -DENABLE_GC=OFF -DENABLE_GTESTS=OFF \
  -DENABLE_PROTOBUF_STATIC=OFF
  make -j4

4. (Optional) Install the compiler:

::

  sudo make install

5. Everything is set and ready to be used. You are able to compile a P4 data
plane compliant to the polycube model using:

::

  p4c-polycube <input>.p4 -o <output>.c

**Option 2: docker image**

Pull the docker image and use the the p4c-polycube compiler installed in it:

::

  docker pull richimarchi/p4c-polycube
  docker run -v <p4_file_folder>:/p4c -it richimarchi/p4c-polycube /bin/bash

  p4c-polycube <input>.p4 -o <output>.c

How it works
************

**Polycube Model**

The polycube model is the architecture to be compliant with, in order to
correctly produce injectable eBPF code. It is described in the file
``p4c/backends/polycube/p4include/polycube_model.p4`` and has 2 sections:
the parser and the filter.
The parser has the job to fill the headers structures, while the filter
represents the service itself with the implementation logic. In order to manage
packet and metadata the way it is done in polycube, the two are added as input
to the second section along with the parsed headers structure.
The control plane of the services is not modified and no special behaviors need
to be implemented, if not the traditional ones already used in most of polycube
services (``pcn_pkt_controller`` packets).

**Main feature: extern functions**

The most important feature of the translation that helps a lot in the
definition of the P4 code is the possibility to use extern functions.
The traditional use results important in the necessity to use C library
functions without having to define them, but simply adding the corresponding
include in the generated code. When declaring the signature, define as ``inout``
the parameters to be passed as reference, as ``in`` the ones unknown at compile
time to be passed as value and nothing for the constants.
Moreover, this feature has been exploited as a workaround in order to define
custom functions added to the model: update and delete for tables management,
preprocessor directive emission, subtractions and pcn_pkt_<method>(...)
functions have been declared in the ``polycube_model.p4`` file as extern, but
are handled in a specific way by the backend.
Here is the declaration:

::

  /**
   * Table management utility functions
   */
  extern void TABLE_UPDATE<T, U>(string t, inout T a, inout U b); /* t.update(&a, &b)*/
  extern void TABLE_DELETE<T>(string t, inout T a); /* t.delete(&a)*/

  /**
   * Utility functions to handle unmanageable translation.
   */
  extern void SUBTRACTION<T>(in T result, in T varA, in T varB); /* result = varA - varB*/
  extern void EMIT_LOC(string t);

  /**
   * Polycube functions to handle packets. "return " is added before them.
   */
  extern void pcn_pkt_redirect(in CTXTYPE skb, in pkt_metadata md, in bit<16> port);
  extern void pcn_pkt_drop(in CTXTYPE skb, in pkt_metadata md);
  extern void pcn_pkt_controller(in CTXTYPE skb, in pkt_metadata md, bit<16> reason);
  extern void pcn_pkt_controller_with_metadata(in CTXTYPE skb, in pkt_metadata md, bit<16> reason,
                                               in bit<32> md0, in bit<32> md1, in bit<32> md2);
  extern void pcn_pkt_redirect_ns(in CTXTYPE skb, in pkt_metadata md, in bit<16> port);

**Rules to follow**

- When declaring the parsing in the P4 parser, the order of OSI protocol stack
  must be respected (the first will be the ethernet header), so that the right
  succession in the offset calculation is guaranteed.

  - Example: if we could have either TCP/IP or ARP, the sequence of
    parsing is ``ETH - IPv4, ARP (in each layer order is irrelevant) - TCP``

- P4 tables are used to read from eBPF tables (to update and delete we use
  extern functions as workaround), but to have a correct translation is
  necessary that each table has only two actions possible, declared in order
  "hit - miss", and the miss one has to be defined as the default one. Since the
  actions of the tables are handled by the frontend, it is strongly suggested to
  assign the return value to a global variable and to handle the logic totally
  in the apply body of the filter (for instance, extern function would not be
  usable, since the management is implemented in the backend).

**Limitations**

P4 has not the same expressiveness compared to C, therefore there are some
aspects not covered in the process that need to be addressed manually by the
programmer after the translation.

- During the compilation phase, the parsing of all the headers is put at the
  beginning, right after the packet reception. The eBPF validator does not allow
  it, therefore we will have to move manually the parsing of each header before the
  effective use.

  - Example: if we parse ethernet and IPv4, here is what we have as result:

    ::

        start: {
        /* extract(hdr.ethernet)*/
        hdr.ethernet = polycube_packetStart;
        if (polycube_packetStart + sizeof(*(hdr.ethernet)) > polycube_packetEnd) {
            goto reject;
        }
        switch (hdr.ethernet->etherType) {
            case 0x800: goto parse_ipv4;
            default: goto accept;
        }
        }
        parse_ipv4: {
            /* extract(hdr.ipv4)*/
            hdr.ipv4 = polycube_packetStart + sizeof(*(hdr.ethernet));
            if (polycube_packetStart + sizeof(*(hdr.ethernet)) + sizeof(*(hdr.ipv4)) > polycube_packetEnd) {
                goto reject;
            }
            switch (hdr.ipv4->protocol) {
                case 6: goto parse_tcp;
                default: goto accept;
            }
        }

    In order to be accepted by the validator, add ``goto accept`` after the check of the ethernet header size and delete the remaining parsing like this:

    ::

        start: {
            /* extract(hdr.ethernet)*/
            hdr.ethernet = polycube_packetStart;
            if (polycube_packetStart + sizeof(*(hdr.ethernet)) > polycube_packetEnd) {
                goto reject;
            }
            goto accept;
        }

    and then move the IPv4 parsing right after the check of the etherType and before the header usage

    ::

        u16 tmp = htons(0x800); /* IPv4 etherType in network byte order */
        if (hdr.ethernet->etherType == tmp) {
            hdr.ipv4 = polycube_packetStart + sizeof(*(hdr.ethernet));
            if (polycube_packetStart + sizeof(*(hdr.ethernet)) + sizeof(*(hdr.ipv4)) > polycube_packetEnd) {
                goto reject;
            }
            /* IPv4 header usage */
            .....
        }

- The P4 code does not support arrays

- Only basic include files are added in the compilation

- Unsupported operations whose results is know a priori (e.g. like ``sizeof
  (struct iphdr)``) must be replaced with the result value.