#! /bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/helpers.bash"

function test_fail {
  set +e
  res=$($@)
  local status=$?
  set -e
  if [ $status -ne 0 ]; then
    return 0
  else
    return 1
  fi
}

# function cleanup: is invoked each time script exit (with or without errors)
# please remember to cleanup all entities previously created:
# namespaces, veth, cubes, ..
function cleanup {
  set +e
  polycubectl p4firewall del fw1
  for i in `seq 1 4`;
  do
  	sudo ip link del veth${i}
  	sudo ip netns del ns${i}
  done
}
trap cleanup EXIT

# Enable verbose output
set -x

# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

for i in `seq 1 4`;
  do
    sudo ip netns del ns${i} || true
  	sudo ip netns add ns${i}
  	sudo ip link add veth${i}_ type veth peer name veth${i}
  	sudo ip link set veth${i}_ netns ns${i}
  	sudo ip netns exec ns${i} ip link set dev veth${i}_ up
  	sudo ip link set dev veth${i} up
  	sudo ip netns exec ns${i} ifconfig veth${i}_ 10.0.${i}.${i}/24
  	sudo ip netns exec ns${i} ifconfig veth${i}_ hw ether 08:00:00:00:0${i}:${i}${i}
  	sudo ip netns exec ns${i} netcat -l 60123&
  	for l in `seq 1 4`;
  	do
  	  if [ $i -ne $l ]; then
        sudo ip netns exec ns${i} ip route add 10.0.${l}.${l} dev veth${i}_
  	  fi
    done
  done


polycubectl p4firewall add fw1
polycubectl fw1 ports add port1
polycubectl fw1 ports add port2
polycubectl fw1 ports add port3
polycubectl fw1 ports add port4

polycubectl connect fw1:port1 veth1
polycubectl connect fw1:port2 veth2
polycubectl connect fw1:port3 veth3
polycubectl connect fw1:port4 veth4

polycubectl fw1 route add 10.0.1.0/24 mac=08:00:00:00:01:11 interface=port1
polycubectl fw1 route add 10.0.2.0/24 mac=08:00:00:00:02:22 interface=port2
polycubectl fw1 route add 10.0.3.0/24 mac=08:00:00:00:03:33 interface=port3
polycubectl fw1 route add 10.0.4.0/24 mac=08:00:00:00:04:44 interface=port4

polycubectl fw1 flow-direction add port1 port3 direction=0
polycubectl fw1 flow-direction add port1 port4 direction=0
polycubectl fw1 flow-direction add port2 port3 direction=0
polycubectl fw1 flow-direction add port2 port4 direction=0

polycubectl fw1 flow-direction add port3 port1 direction=1
polycubectl fw1 flow-direction add port3 port2 direction=1
polycubectl fw1 flow-direction add port4 port1 direction=1
polycubectl fw1 flow-direction add port4 port2 direction=1

sudo ip netns exec ns4 ping 10.0.1.1 -w 4
test_fail sudo ip netns exec ns3 netcat -nvz 10.0.2.2 60123 -w 4
test_fail sudo ip netns exec ns4 netcat -nvz 10.0.1.1 60123 -w 4
sudo ip netns exec ns1 netcat -nvz 10.0.2.2 60123 -w 4
sudo ip netns exec ns2 netcat -nvz 10.0.3.3 60123 -w 4
sudo ip netns exec ns1 netcat -nvz 10.0.4.4 60123 -w 4
sudo ip netns exec ns2 netcat -nvz 10.0.1.1 60123 -w 4
