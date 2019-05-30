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
  std::map<std::string, nlohmann::json> Resource::cubesConfig;
  std::condition_variable Resource::data_cond;
  bool Resource::kill = false;
  std::atomic<int> Resource::toSave = 0;

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

void Resource::UpdateCubesConfig(const std::string& serviceName,
                                 const std::string& cubeName,
                                 nlohmann::json body,
                                 Operation opType) {

  std::lock_guard<std::mutex> lg(mutex);
  if (opType == Operation::kDelete) {
    if (body.empty()) {
      cubesConfig.erase(cubeName);
    } else {
      for (int i = 0; i < cubesConfig[cubeName][serviceName].size(); i++) {
        if (cubesConfig[cubeName][serviceName][i]["name"] == body["name"]) {
          cubesConfig[cubeName][serviceName].erase(i);
          break;
        }
      }
      if (cubesConfig[cubeName][serviceName].empty()) {
        cubesConfig[cubeName].erase(serviceName);
      }
    }
  } else {
    if (cubesConfig.find(cubeName) == cubesConfig.end()) {
      nlohmann::json serviceField = nlohmann::json::object();
      serviceField["service-name"] = serviceName;
      serviceField.update(body);
      cubesConfig[cubeName].update(serviceField);
    } else {
      if (cubesConfig[cubeName].find(serviceName) == cubesConfig[cubeName].end()) {
        nlohmann::json toUpdate = nlohmann::json::array();
        toUpdate.push_back(body);
        cubesConfig[cubeName][serviceName] = toUpdate;
      } else {
        if (cubesConfig[cubeName][serviceName].type() == nlohmann::json::value_t::array) {
          cubesConfig[cubeName][serviceName].push_back(body);
        } else {
          cubesConfig[cubeName][serviceName] = body;
        }
      }
    }
  }

  if (!RestServer::startup) {
    toSave++;
    data_cond.notify_one();
  }
}

void Resource::SaveToFile(const std::string& path) {
  while (true) {
    std::unique_lock<std::mutex> uniqueLock(mutex);
    if (toSave.load() == 0) {
      data_cond.wait(uniqueLock);
    }
    if (kill) {
      break;
    }
    std::map<std::string, nlohmann::json> copyConfig(cubesConfig);
    toSave.store(0);
    uniqueLock.unlock();
    std::ofstream myFile(path);
    if (myFile.is_open()) {
      nlohmann::json toDump = nlohmann::json::array();
      for (const auto &elem : copyConfig) {
        auto cube = elem.second;
        toDump += cube;
      }
      myFile << toDump.dump(2);
      myFile.close();
    }
  }
}

}  // namespace polycube::polycubed::Rest::Resources::Endpoint
