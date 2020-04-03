P4 Firewall
===========

This service implements a basic firewall, that blocks TCP packets incoming in a
network if the connection is not started from inside of it yet.

Features
--------

- IPv4 forwarding with static routes
- Incoming and outgoing flow distinguished with static port mapping
- Non-IPv4 packets are flooded
- Unknown routes are flooded
- Unknown port mappings are forwarded
- Non-TCP packets are forwarded

How to use
----------

Important note about how it works
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The implementation of the fast path is very basic: If the TCP packet is going
out of the internal network and it is a SYN packet, insert the session in the
fast path session table. Otherwise, if the TCP packet is entering the internal
network,check if there's an active session and drop the packet if it is not
found. Two hosts belonging both inside or outside the network can connect
without being tracked by the firewall.
The slow path is used only to flood non-IPv4 packets or the ones with an unknown
route.

Example
^^^^^^^

Once deployed the p4firewall instance and the ports needed, configure it by
setting routes and port mappings to decide how to manage the traffic as done in
the example below:

::

  # add route
  polycubectl fw1 route add 10.0.1.0/24 mac=08:00:00:00:01:11 interface=port1

  # set as outgoing traffic
  polycubectl fw1 flow-direction add port1 port2 direction=0

  # set as incoming traffic
  polycubectl fw1 flow-direction add port2 port1 direction=1