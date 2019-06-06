/**
* firewall API generated from firewall.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */


#include "ChainRuleBase.h"
#include "../Firewall.h"


ChainRuleBase::ChainRuleBase(Chain &parent)
    : parent_(parent) {}

ChainRuleBase::~ChainRuleBase() {}

void ChainRuleBase::update(const ChainRuleJsonObject &conf) {

}

ChainRuleJsonObject ChainRuleBase::toJsonObject() {
  ChainRuleJsonObject conf;

  conf.setId(getId());
  conf.setSrc(getSrc());
  conf.setDst(getDst());
  conf.setL4proto(getL4proto());
  conf.setSport(getSport());
  conf.setDport(getDport());
  conf.setTcpflags(getTcpflags());
  conf.setConntrack(getConntrack());
  conf.setAction(getAction());
  conf.setDescription(getDescription());

  return conf;
}

std::shared_ptr<spdlog::logger> ChainRuleBase::logger() {
  return parent_.logger();
}
