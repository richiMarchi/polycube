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


#include "FlowDirection.h"
#include "P4firewall.h"


FlowDirection::FlowDirection(P4firewall &parent, const FlowDirectionJsonObject &conf)
    : FlowDirectionBase(parent) {
}

FlowDirection::FlowDirection(P4firewall &parent, std::string &src, std::string &dst, uint8_t &direction)
    : FlowDirectionBase(parent), srcInterface_(src), dstInterface_(dst), direction_(direction) {}

FlowDirection::~FlowDirection() {}

std::string FlowDirection::getSrcInterface() {
  return srcInterface_;
}

std::string FlowDirection::getDstInterface() {
  return dstInterface_;
}

uint8_t FlowDirection::getDirection() {
  return direction_;
}


