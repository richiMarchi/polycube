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

#define SAVE_PATH "/etc/polycube/cubes.yaml"

namespace polycube::polycubed::Rest::Resources::Endpoint {

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

void Resource::SaveToFile(std::string cubes) {
  std::ofstream myFile (SAVE_PATH);
  if (myFile.is_open()) {
    nlohmann::json j = nlohmann::json::parse(cubes);
    nlohmann::json toDump = nlohmann::json::array();
    for (auto &service : j) {
      for (auto &cube : service) {
        cube.erase("uuid");
        toDump += cube;
      }
    }
    myFile << toDump.dump(2);
    myFile.close();
  }
}

}  // namespace polycube::polycubed::Rest::Resources::Endpoint
