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


#include "../base/FlowDirectionBase.h"


class P4firewall;

using namespace polycube::service::model;

struct cp_k {
  uint32_t  ingress_port; /* bit<16> */
  uint32_t egress_spec; /* bit<16> */
} __attribute__((packed));

class FlowDirection : public FlowDirectionBase {
 public:
  FlowDirection(P4firewall &parent, const FlowDirectionJsonObject &conf);
  FlowDirection(P4firewall &parent, std::string &src, std::string &dst, uint8_t &direction);
  virtual ~FlowDirection();

  /// <summary>
  /// In port.
  /// </summary>
  std::string getSrcInterface() override;

  /// <summary>
  /// Out port.
  /// </summary>
  std::string getDstInterface() override;

  /// <summary>
  /// Inboud or outbound
  /// </summary>
  uint8_t getDirection() override;

private:
  std::string srcInterface_;
  std::string dstInterface_;
  uint8_t direction_;
};
