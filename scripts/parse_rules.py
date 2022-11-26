# parse rules to recognize catched log tags and category
# rules should use hashtag# to identify the level of title

import re

class RuleType:
  def __init__(self, category, description = "", tag = "") -> None:
    self.category = category
    self.description = description
    self.tag = tag
    self.logs = []

class CatchRules:
  def __init__(self) -> None:
    self.rules = {}

  def add_rule(self, rule_type):
    cate = rule_type.category
    try:
      self.rules[cate].append(rule_type)
    except:
      self.rules[cate] = [rule_type]
  
  def __str__(self) -> str:
    rules_str = ""
    for cate, rules in self.rules.items():
      rules_str += cate + ':\n'
      for rule in rules:
        rules_str += '\tdescription: '+rule.description+'\n'
        rules_str += '\ttag: '+rule.tag+'\n'
    return rules_str

def parse_rules(rule_file, log_types):
  with open(rule_file,'r', encoding='utf-8') as f:
    cate = ""
    despt = ""
    while(True):
      line = f.readline()
      if (not line):
        break
      level2_res = re.search("\A##\s", line)
      level3_res = re.search("\A###\s", line)
      tag = re.findall("-k\s(\w*)", line)
      if (level2_res):
        cate = " ".join(line.split()[1:])
        despt = ""
      elif (level3_res):
        despt = " ".join(line.split()[1:])
      elif (tag):
        tag = tag[0]
        rule = RuleType(cate, despt, tag)
        log_types.add_rule(rule)

log_types = CatchRules()
parse_rules("../rules/example.rules", log_types)
print(log_types)