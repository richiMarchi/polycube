/**
* lbrp API
* lbrp API generated from lbrp.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "SrcIpRewriteJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

SrcIpRewriteJsonObject::SrcIpRewriteJsonObject() {
  m_ipRangeIsSet = false;
  m_newIpRangeIsSet = false;
}

SrcIpRewriteJsonObject::SrcIpRewriteJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_ipRangeIsSet = false;
  m_newIpRangeIsSet = false;


  if (val.count("ip-range")) {
    setIpRange(val.at("ip-range").get<std::string>());
  }

  if (val.count("new_ip_range")) {
    setNewIpRange(val.at("new_ip_range").get<std::string>());
  }
}

nlohmann::json SrcIpRewriteJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_ipRangeIsSet) {
    val["ip-range"] = m_ipRange;
  }

  if (m_newIpRangeIsSet) {
    val["new_ip_range"] = m_newIpRange;
  }

  return val;
}

std::string SrcIpRewriteJsonObject::getIpRange() const {
  return m_ipRange;
}

void SrcIpRewriteJsonObject::setIpRange(std::string value) {
  m_ipRange = value;
  m_ipRangeIsSet = true;
}

bool SrcIpRewriteJsonObject::ipRangeIsSet() const {
  return m_ipRangeIsSet;
}

void SrcIpRewriteJsonObject::unsetIpRange() {
  m_ipRangeIsSet = false;
}

std::string SrcIpRewriteJsonObject::getNewIpRange() const {
  return m_newIpRange;
}

void SrcIpRewriteJsonObject::setNewIpRange(std::string value) {
  m_newIpRange = value;
  m_newIpRangeIsSet = true;
}

bool SrcIpRewriteJsonObject::newIpRangeIsSet() const {
  return m_newIpRangeIsSet;
}

void SrcIpRewriteJsonObject::unsetNewIpRange() {
  m_newIpRangeIsSet = false;
}


}
}
}
}

