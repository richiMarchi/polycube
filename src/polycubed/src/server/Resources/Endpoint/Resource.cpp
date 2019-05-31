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
                                 const std::string& resource,
                                 nlohmann::json body,
                                 Operation opType) {

  std::stringstream ss(resource);
  std::vector<std::string> resItem;
  std::string token;

  while(std::getline(ss, token, '/')) {
    resItem.push_back(token);
  }

  std::lock_guard<std::mutex> lg(mutex);
  switch (opType) {
    case Operation::kCreate:case Operation::kReplace: {
      if (resItem.size() == 5) {
        nlohmann::json serviceField = nlohmann::json::object();
        serviceField["service-name"] = serviceName;
        serviceField.update(body);
        if (cubesConfig.find(cubeName) != cubesConfig.end()) {
          cubesConfig.erase(cubeName);
        }
        cubesConfig[cubeName].update(serviceField);
      } else {
        nlohmann::json *item = &cubesConfig[resItem[4]];
        for (int i = 5; i < resItem.size() - 1; i++) {
          auto *el = &item[0][resItem[i]];
          if (el->is_null()) {
            nlohmann::json toUpdate = nlohmann::json::array();
            toUpdate.push_back(body);
            item[0][resItem[i]] = toUpdate;
            break;
          } else if (el->is_array()) {
            if (i == resItem.size() - 2) {
              if (el->find(resItem[i + 1]) != el->end()) {
                el->erase(resItem[i + 1]);
              }
              el[0].push_back(body);
            } else {
              for (int j = 0; j < el->size(); j++) {
                if (el[0][j]["name"] == resItem[i + 1]) {
                  el = &item[0][resItem[i]][j];
                  i++;
                  break;
                }
              }
            }
          } else {
            if (i == resItem.size() - 2) {
              item[0][resItem[i]] = body;
            }
          }
          item = el;
        }
      }
      break;
    }

    case Operation::kUpdate: {
      nlohmann::json *item = &cubesConfig[resItem[4]];
      for (int i = 5; i < resItem.size() - 1; i++) {
        auto *el = &item[0][resItem[i]];
        if (el->is_array()) {
          for (int j = 0; j < el->size(); j++) {
            if (el[0][j]["name"] == resItem[i + 1]) {
              el = &item[0][resItem[i]][j];
              i++;
              break;
            }
          }
        }
        item = el;
      }

      item[0][resItem[resItem.size() - 1]] = body;
      break;
    }

    case Operation::kDelete: {
      if (resItem.size() == 5) {
        cubesConfig.erase(cubeName);
      } else {
        nlohmann::json *item = &cubesConfig[resItem[4]];
        bool deleted = false;
        for (int i = 5; i < resItem.size() - 1; i++) {
          auto *el = &item[0][resItem[i]];
          if (el->is_array()) {
            for (int j = 0; j < el->size(); j++) {
              if (el[0][j]["name"] == resItem[i + 1]) {
                if (i == resItem.size() - 2) {
                  el->erase(j);
                  deleted = true;
                  if (el->empty()) {
                    item->erase(resItem[i]);
                  }
                } else {
                  el = &item[0][resItem[i]][i];
                  i++;
                }
                break;
              }
            }
          }
          item = el;
        }
        if (!deleted) {
          item->erase(resItem[resItem.size() - 1]);
        }
      }
      break;
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
