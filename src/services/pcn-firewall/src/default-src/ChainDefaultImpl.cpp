/**
* firewall API
* firewall API generated from firewall.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/

// These methods have a default implementation. Your are free to keep it or add
// your own

#include "../Chain.h"

std::shared_ptr<ChainStats> Chain::getStats(const uint32_t &id) {
  return ChainStats::getEntry(*this, id);
}

std::vector<std::shared_ptr<ChainStats>> Chain::getStatsList() {
  return ChainStats::get(*this);
}

void Chain::addStats(const uint32_t &id, const ChainStatsJsonObject &conf) {
  ChainStats::create(*this, id, conf);
}

void Chain::addStatsList(const std::vector<ChainStatsJsonObject> &conf) {
  for (auto &i : conf) {
    uint32_t id_ = i.getId();
    ChainStats::create(*this, id_, i);
  }
}

void Chain::replaceStats(const uint32_t &id, const ChainStatsJsonObject &conf) {
  ChainStats::removeEntry(*this, id);
  uint32_t id_ = conf.getId();
  ChainStats::create(*this, id_, conf);
}

void Chain::delStats(const uint32_t &id) {
  ChainStats::removeEntry(*this, id);
}

void Chain::delStatsList() {
  ChainStats::remove(*this);
}

std::shared_ptr<ChainRule> Chain::getRule(const uint32_t &id) {
  return ChainRule::getEntry(*this, id);
}

/*Different from the auto generated!*/
std::vector<std::shared_ptr<ChainRule>> Chain::getRuleList() {
  auto rules = ChainRule::get(*this);

  // Adding a "stub" default rule
  ChainRuleJsonObject defaultRule;
  defaultRule.setAction(getDefault());
  defaultRule.setDescription("Default Policy");
  defaultRule.setId(0);

  rules.push_back(
      std::shared_ptr<ChainRule>(new ChainRule(*this, defaultRule)));

  return rules;
}

void Chain::addRule(const uint32_t &id, const ChainRuleJsonObject &conf) {
  ChainRule::create(*this, id, conf);
}

void Chain::addRuleList(const std::vector<ChainRuleJsonObject> &conf) {
  for (auto &i : conf) {
    uint32_t id_ = i.getId();
    ChainRule::create(*this, id_, i);
  }
}

void Chain::replaceRule(const uint32_t &id, const ChainRuleJsonObject &conf) {
  ChainRule::removeEntry(*this, id);
  uint32_t id_ = conf.getId();
  ChainRule::create(*this, id_, conf);
}

void Chain::delRule(const uint32_t &id) {
  ChainRule::removeEntry(*this, id);
}

void Chain::delRuleList() {
  ChainRule::remove(*this);
}
