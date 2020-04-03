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


// TODO: Modify these methods with your own implementation


#include <tins/tins.h>
#include "P4firewall.h"
#include "P4firewall_dp.h"

#define REASON_FLOODING 1

P4firewall::P4firewall(const std::string name, const P4firewallJsonObject &conf)
  : Cube(conf.getBase(), { p4firewall_code }, {}),
    P4firewallBase(name) {
  logger()->info("Creating P4firewall instance");
  addPortsList(conf.getPorts());
  addFlowDirectionList(conf.getFlowDirection());
  addRouteList(conf.getRoute());
}


P4firewall::~P4firewall() {
  logger()->info("Destroying P4firewall instance");
}

void P4firewall::packet_in(Ports &port,
    polycube::service::PacketInMetadata &md,
    const std::vector<uint8_t> &packet) {

  if (md.reason == REASON_FLOODING) {
    EthernetII p(&packet[0], packet.size());

    for (auto &it : get_ports()) {
      if (it->name() == port.name()) {
        continue;
      }
      it->send_packet_out(p);
      logger()->trace("Packet sent to port {0} as result of flooding",
                      it->name());
    }
  } else {
    logger()->debug("Packet received from port {0}, but the reason isn't flooding", port.name());
  }
}

// Basic default implementation, place your extension here (if needed)
std::shared_ptr<Ports> P4firewall::getPorts(const std::string &name) {
  // call default implementation in base class
  return P4firewallBase::getPorts(name);
}

// Basic default implementation, place your extension here (if needed)
std::vector<std::shared_ptr<Ports>> P4firewall::getPortsList() {
  // call default implementation in base class
  return P4firewallBase::getPortsList();
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::addPorts(const std::string &name, const PortsJsonObject &conf) {
  P4firewallBase::addPorts(name, conf);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::addPortsList(const std::vector<PortsJsonObject> &conf) {
  // call default implementation in base class
  P4firewallBase::addPortsList(conf);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::replacePorts(const std::string &name, const PortsJsonObject &conf) {
  // call default implementation in base class
  P4firewallBase::replacePorts(name, conf);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::delPorts(const std::string &name) {
  // call default implementation in base class
  P4firewallBase::delPorts(name);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::delPortsList() {
  // call default implementation in base class
  P4firewallBase::delPortsList();
}
std::shared_ptr<FlowDirection> P4firewall::getFlowDirection(const std::string &srcInterface, const std::string &dstInterface) {
  throw std::runtime_error("P4firewall::getEntry: Method not implemented");
}

std::vector<std::shared_ptr<FlowDirection>> P4firewall::getFlowDirectionList() {

  std::vector<std::shared_ptr<FlowDirection>> flowDirectionList;

  try {
    auto directionTable = get_hash_table<cp_k, uint8_t>("check_ports");
    auto directionTableList = directionTable.get_all();

    for (auto entry : directionTableList) {
      auto key = entry.first;
      auto value = entry.second;

      std::string src = get_port(key.ingress_port)->name();
      std::string dst = get_port(key.egress_spec)->name();

      flowDirectionList.push_back(
          std::make_shared<FlowDirection>(FlowDirection(*this, src, dst, value)));
    }

  } catch (std::exception &e) {
    throw std::runtime_error("Error in retrieving the table content");
  }

  return flowDirectionList;
}

void P4firewall::addFlowDirection(const std::string &srcInterface, const std::string &dstInterface, const FlowDirectionJsonObject &conf) {

  uint8_t direction = conf.getDirection();
  if (direction > 1)
    throw std::runtime_error("Only 0 (coming from internal network) and 1 (coming from external network) are admitted");

  try {
    uint32_t src = get_port(srcInterface)->index();
    uint32_t dst = get_port(dstInterface)->index();

    cp_k key = {src, dst};

    auto directionTable = get_hash_table<cp_k, uint8_t>("check_ports");
    directionTable.set(key, direction);
  } catch (std::exception &e) {
    throw std::runtime_error("Failed to load the flow direction");
  }
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::addFlowDirectionList(const std::vector<FlowDirectionJsonObject> &conf) {
  // call default implementation in base class
  P4firewallBase::addFlowDirectionList(conf);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::replaceFlowDirection(const std::string &srcInterface, const std::string &dstInterface, const FlowDirectionJsonObject &conf) {
  // call default implementation in base class
  P4firewallBase::replaceFlowDirection(srcInterface, dstInterface, conf);
}

void P4firewall::delFlowDirection(const std::string &srcInterface, const std::string &dstInterface) {
  throw std::runtime_error("P4firewall::delFlowDirection: Method not implemented");
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::delFlowDirectionList() {
  // call default implementation in base class
  P4firewallBase::delFlowDirectionList();
}
std::shared_ptr<Route> P4firewall::getRoute(const std::string &address) {
  throw std::runtime_error("P4firewall::getEntry: Method not implemented");
}

std::vector<std::shared_ptr<Route>> P4firewall::getRouteList() {

  std::vector<std::shared_ptr<Route>> routeList;

  try {
    auto routingTable = get_hash_table<ipv4_fw_k, ipv4_fw_v>("ipv4_lpm");
    auto routingTableEntries = routingTable.get_all();

    for (auto entry : routingTableEntries) {
      auto key = entry.first;
      auto value = entry.second;

      std::string ipAddr = nbo_uint_to_ip_string(key.address);
      std::string macAddr = nbo_uint_to_mac_string(value.dstAddr);
      std::string port = get_port(value.port)->name();

      routeList.push_back(
          std::make_shared<Route>(Route(*this, ipAddr, macAddr, port)));
    }

  } catch (std::exception &e) {
    throw std::runtime_error("Error in retrieving the table content");
  }

  return routeList;
}

void P4firewall::addRoute(const std::string &address, const RouteJsonObject &conf) {

  try {
    std::string ip_route;
    std::string netmask_route;
    split_ip_and_prefix(address, ip_route, netmask_route);

    uint32_t networkDec;
    uint32_t netmask;
    if (netmask_route != "255.255.255.255") {
      networkDec = ip_string_to_nbo_uint(ip_route) &
                            ip_string_to_nbo_uint(netmask_route);
      netmask = get_netmask_length(netmask_route);
    } else {
      networkDec = ip_string_to_nbo_uint(ip_route);
      netmask = 32;
    }

    uint64_t macAddr = mac_string_to_nbo_uint(conf.getMac());
    uint32_t port = get_port(conf.getInterface())->index();

    ipv4_fw_k key = {.netmask = netmask, .address = networkDec };
    ipv4_fw_v value = {.dstAddr = macAddr, .port = port};

    auto routingTable = get_hash_table<ipv4_fw_k, ipv4_fw_v>("ipv4_lpm");
    routingTable.set(key, value);
  } catch (std::exception &e) {
    throw std::runtime_error(e.what());
  }
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::addRouteList(const std::vector<RouteJsonObject> &conf) {
  // call default implementation in base class
  P4firewallBase::addRouteList(conf);
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::replaceRoute(const std::string &address, const RouteJsonObject &conf) {
  // call default implementation in base class
  P4firewallBase::replaceRoute(address, conf);
}

void P4firewall::delRoute(const std::string &address) {
  throw std::runtime_error("P4firewall::delRoute: Method not implemented");
}

// Basic default implementation, place your extension here (if needed)
void P4firewall::delRouteList() {
  // call default implementation in base class
  P4firewallBase::delRouteList();
}


