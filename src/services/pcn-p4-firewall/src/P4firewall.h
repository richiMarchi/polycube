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


#include "../base/P4firewallBase.h"

#include "FlowDirection.h"
#include "Ports.h"
#include "Route.h"


using namespace polycube::service::model;
using namespace polycube::service::utils;
using namespace polycube::service;
using namespace Tins;

class P4firewall : public P4firewallBase {
 public:
  P4firewall(const std::string name, const P4firewallJsonObject &conf);
  virtual ~P4firewall();

  void packet_in(Ports &port,
                 polycube::service::PacketInMetadata &md,
                 const std::vector<uint8_t> &packet) override;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  std::shared_ptr<Ports> getPorts(const std::string &name) override;
  std::vector<std::shared_ptr<Ports>> getPortsList() override;
  void addPorts(const std::string &name, const PortsJsonObject &conf) override;
  void addPortsList(const std::vector<PortsJsonObject> &conf) override;
  void replacePorts(const std::string &name, const PortsJsonObject &conf) override;
  void delPorts(const std::string &name) override;
  void delPortsList() override;

  /// <summary>
  ///
  /// </summary>
  std::shared_ptr<FlowDirection> getFlowDirection(const std::string &srcInterface, const std::string &dstInterface) override;
  std::vector<std::shared_ptr<FlowDirection>> getFlowDirectionList() override;
  void addFlowDirection(const std::string &srcInterface, const std::string &dstInterface, const FlowDirectionJsonObject &conf) override;
  void addFlowDirectionList(const std::vector<FlowDirectionJsonObject> &conf) override;
  void replaceFlowDirection(const std::string &srcInterface, const std::string &dstInterface, const FlowDirectionJsonObject &conf) override;
  void delFlowDirection(const std::string &srcInterface, const std::string &dstInterface) override;
  void delFlowDirectionList() override;

  /// <summary>
  /// Entry associated with the ARP table
  /// </summary>
  std::shared_ptr<Route> getRoute(const std::string &address) override;
  std::vector<std::shared_ptr<Route>> getRouteList() override;
  void addRoute(const std::string &address, const RouteJsonObject &conf) override;
  void addRouteList(const std::vector<RouteJsonObject> &conf) override;
  void replaceRoute(const std::string &address, const RouteJsonObject &conf) override;
  void delRoute(const std::string &address) override;
  void delRouteList() override;
};
