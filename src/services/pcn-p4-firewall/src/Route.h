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


#pragma once


#include "../base/RouteBase.h"


class P4firewall;

using namespace polycube::service::model;

struct ipv4_fw_v {
  uint64_t dstAddr : 48; /* bit<48> */
  uint32_t port; /* bit<16> */
} __attribute__((packed));

struct ipv4_fw_k {
  uint32_t netmask; /* bit<32> */
  uint32_t address; /* bit<32> */
} __attribute__((packed));

class Route : public RouteBase {
 public:
  Route(P4firewall &parent, const RouteJsonObject &conf);
  Route(P4firewall &parent, std::string &ipAddr, std::string &macAddr, std::string &port);
  virtual ~Route();

  /// <summary>
  /// Destination IP address
  /// </summary>
  std::string getAddress() override;

  /// <summary>
  /// Destination MAC address
  /// </summary>
  std::string getMac() override;
  void setMac(const std::string &value) override;

  /// <summary>
  /// Outgoing interface
  /// </summary>
  std::string getInterface() override;
  void setInterface(const std::string &value) override;

private:
  std::string k_addr_;
  std::string v_dstAddr_;
  std::string v_port_;
};
