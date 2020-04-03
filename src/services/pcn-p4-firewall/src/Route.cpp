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


#include "Route.h"
#include "P4firewall.h"


Route::Route(P4firewall &parent, const RouteJsonObject &conf)
    : RouteBase(parent) {
    setMac(conf.getMac());
    setInterface(conf.getInterface());
}

Route::Route(P4firewall &parent, std::string &ipAddr,  std::string &macAddr, std::string &port)
    : RouteBase(parent), k_addr_(ipAddr), v_dstAddr_(macAddr), v_port_(port) {}

Route::~Route() {}

std::string Route::getAddress() {
  return k_addr_;
}

std::string Route::getMac() {
  return v_dstAddr_;
}

void Route::setMac(const std::string &value) {
  this->v_dstAddr_ = value;
}

std::string Route::getInterface() {
  return v_port_;
}

void Route::setInterface(const std::string &value) {
  this->v_port_ = value;
}


