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

/*
* FdbFlushOutputJsonObject.h
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
class  FdbFlushOutputJsonObject : public JsonObjectBase {
public:
  FdbFlushOutputJsonObject();
  FdbFlushOutputJsonObject(const nlohmann::json &json);
  ~FdbFlushOutputJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Returns true if the Filtering database has been flushed. False otherwise
  /// </summary>
  bool getFlushed() const;
  void setFlushed(bool value);
  bool flushedIsSet() const;

private:
  bool m_flushed;
  bool m_flushedIsSet;
};

}
}
}
}

