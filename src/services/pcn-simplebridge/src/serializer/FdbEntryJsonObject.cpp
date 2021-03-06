/**
* simplebridge API
* simplebridge API generated from simplebridge.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "FdbEntryJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

FdbEntryJsonObject::FdbEntryJsonObject() {
  m_addressIsSet = false;
  m_portIsSet = false;
  m_ageIsSet = false;
}

FdbEntryJsonObject::FdbEntryJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_addressIsSet = false;
  m_portIsSet = false;
  m_ageIsSet = false;


  if (val.count("address")) {
    setAddress(val.at("address").get<std::string>());
  }

  if (val.count("port")) {
    setPort(val.at("port").get<std::string>());
  }

  if (val.count("age")) {
    setAge(val.at("age").get<uint32_t>());
  }
}

nlohmann::json FdbEntryJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_addressIsSet) {
    val["address"] = m_address;
  }

  if (m_portIsSet) {
    val["port"] = m_port;
  }

  if (m_ageIsSet) {
    val["age"] = m_age;
  }

  return val;
}

std::string FdbEntryJsonObject::getAddress() const {
  return m_address;
}

void FdbEntryJsonObject::setAddress(std::string value) {
  m_address = value;
  m_addressIsSet = true;
}

bool FdbEntryJsonObject::addressIsSet() const {
  return m_addressIsSet;
}



std::string FdbEntryJsonObject::getPort() const {
  return m_port;
}

void FdbEntryJsonObject::setPort(std::string value) {
  m_port = value;
  m_portIsSet = true;
}

bool FdbEntryJsonObject::portIsSet() const {
  return m_portIsSet;
}



uint32_t FdbEntryJsonObject::getAge() const {
  return m_age;
}

void FdbEntryJsonObject::setAge(uint32_t value) {
  m_age = value;
  m_ageIsSet = true;
}

bool FdbEntryJsonObject::ageIsSet() const {
  return m_ageIsSet;
}

void FdbEntryJsonObject::unsetAge() {
  m_ageIsSet = false;
}


}
}
}
}

