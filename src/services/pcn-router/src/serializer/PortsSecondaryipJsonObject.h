/**
* router API
* router API generated from router.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* PortsSecondaryipJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  PortsSecondaryipJsonObject : public JsonObjectBase {
public:
  PortsSecondaryipJsonObject();
  PortsSecondaryipJsonObject(const nlohmann::json &json);
  ~PortsSecondaryipJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Seconadary IP address of the port
  /// </summary>
  std::string getIp() const;
  void setIp(std::string value);
  bool ipIsSet() const;

  /// <summary>
  /// Secondary netmask of the port
  /// </summary>
  std::string getNetmask() const;
  void setNetmask(std::string value);
  bool netmaskIsSet() const;

private:
  std::string m_ip;
  bool m_ipIsSet;
  std::string m_netmask;
  bool m_netmaskIsSet;
};

}
}
}
}

