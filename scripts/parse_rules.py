# parse rules to recognize catched log tags and category
# rules should use hashtag# to identify the level of title

import re

class RuleType:
  def __init__(self, category="", tag = "", description = "", rule = "", type = "syscall") -> None:
    self.category = category
    self.description = description
    self.tag = tag
    self.rule = rule
    self.type = type
  
  def __str__(self) -> str:
    str = " | "
    cate = "Category: " + self.category
    desp = "Description: " + self.description
    tag = "Tag: " + self.tag
    type = "Type: " + self.type
    rule = "Rule: " + self.rule
    return str.join([cate, desp, tag, type])

  def parse_jsons(self, str):
    cate = re.findall("Category:\s([\w\s]*)\s?\|?",str)[0].strip()
    desp = re.findall("Description:\s([\w\s]*)\s?\|?",str)[0].strip()
    tag = re.findall("Tag:\s([\w\s]*)\s?\|?",str)[0].strip()
    type = re.findall("Type:\s([\w\s]*)\s?\|?",str)[0].strip()
    ruletype = RuleType(category=cate, tag=tag, description=desp, type=type)
    return ruletype

class CatchRules:
  # create a CatchRules object containing a map with
  # category as the key, RuleType objects as the value
  def __init__(self, rule_file = "../rules/example.rules") -> None:
    self.rules = {}
    self.parse_rules(rule_file)

  def add_rule(self, rule_type):
    cate = rule_type.category
    try:
      self.rules[cate].append(rule_type)
    except:
      self.rules[cate] = [rule_type]
  
  # return a list of rules maching the tagname
  def search_rule(self, tagname):
    tag_rules = []
    for cate, rules in self.rules.items():
      for rule in rules:
        if rule.tag == tagname:
          tag_rules.append(rule)
    if (tag_rules == []):
      print("no such tag!", tagname)
    return tag_rules

  # the category starts with ##
  # the description starts with ###
  def parse_rules(self, rule_file):
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
          find_w = re.search("-w\s", line)
          if find_w:
            type = "file"
          else:
            type = "syscall"
          rule = RuleType(cate, tag, despt, line, type)
          self.add_rule(rule)

  def __str__(self) -> str:
    rules_str = ""
    for cate, rules in self.rules.items():
      rules_str += cate + ':\n'
      for rule in rules:
        rules_str += rule.__str__()
    return rules_str

def main():
  log_types = CatchRules("../rules/example.rules")
  # print(log_types)
  return log_types

def test(log_types):
  rule_type = CatchRules().search_rule("sbin_susp")
  for rule in rule_type:
    print(rule)

if __name__ == "__main__":
  log_types = main()
  test(log_types)