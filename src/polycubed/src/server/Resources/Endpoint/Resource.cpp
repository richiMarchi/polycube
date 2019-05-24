#include <utility>

#include <utility>

/*
 * Copyright 2018 The Polycube Authors
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
#include "Resource.h"

#include <string>
#include <fstream>
#include <rest_server.h>
#include <config.h>

namespace polycube::polycubed::Rest::Resources::Endpoint {

  std::mutex Resource::mutex;
  std::map<std::string, std::string> Resource::cubesConfig;
  std::condition_variable Resource::data_cond;
  bool Resource::kill = false;

Resource::Resource(const std::string &rest_endpoint)
    : rest_endpoint_{rest_endpoint} {}

Operation Resource::OperationType(bool update, bool initialization) {
  if (!update) {
    return Operation::kCreate;
  } else {
    if (initialization) {
      return Operation::kReplace;
    } else {
      return Operation::kUpdate;
    }
  }
}

void Resource::UpdateCubesConfig(const std::string& cubeName, std::string cube, bool remove) {
  if (remove)
    cubesConfig.erase(cubeName);
  else
    cubesConfig[cubeName] = cube;
  if (!RestServer::startup)
    data_cond.notify_one();
}

void Resource::SaveToFile(const std::string& path) {
  while (true) {
    std::unique_lock<std::mutex> uniqueLock(mutex);
    data_cond.wait(uniqueLock);
    if (kill)
      break;
    std::ofstream myFile(path);
    if (myFile.is_open()) {
      nlohmann::json toDump = nlohmann::json::array();
      nlohmann::json cube;
      for (const auto &elem : cubesConfig) {
        cube = nlohmann::json::parse(elem.second);
        cube.erase("uuid");
        toDump += cube;
      }
      myFile << toDump.dump(2);
      myFile.close();
    }
    uniqueLock.unlock();
  }
}

}  // namespace polycube::polycubed::Rest::Resources::Endpoint
