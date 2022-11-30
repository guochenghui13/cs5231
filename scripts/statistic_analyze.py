from parse_rules import *
from parse_logs import log_file
import json
import pandas as pd
import sys
import plotly.express as px

log_file = "../logs/auditbeat-20221127.ndjson"
parsed_log_file = ".."+log_file.split('.')[2]+"_filtered.json"

time_dic = {}
tag_dic = {}
file_dic = {}

def collect_statistic(parsed_log_file, time_dic, tag_dic, file_dic):
  i = 0
  with open(parsed_log_file, "r", encoding="utf-8") as f:
    line = f.readline()
    while(True):
      i = i + 1
      if (not line):
        break
      obj = json.loads(line)
      # print(i)
      
      ruletype = RuleType().parse_jsons(obj['rule'])
      log = json.loads(obj['log'])
      ## print(ruletype)
      ## print(log)

      # collect time info
      timestamp = log['timestamp']
      try:
        time_dic[timestamp] = time_dic[timestamp] + 1
      except:
        time_dic[timestamp] = 1
      
      # collect log tag
      tag = ruletype.tag
      try:
        tag_dic[tag] = tag_dic[tag] + 1
      except:
        tag_dic[tag] = 1

      # collect filename info
      try:
        filename = log['accessed_file']
        try:
          file_dic[filename] = file_dic[filename] + 1
        except:
          file_dic[filename] = 1
      except:
        pass

      line = f.readline()

def print_util():
  print("Please indicate a statistic graph to see, default: time")
  print("Available options: time, tag, file")

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print_util()
    exit()
  
  collect_statistic(parsed_log_file, time_dic, tag_dic, file_dic)
  mode = sys.argv[1]

  if mode == "tag":
    tag_df = pd.DataFrame.from_dict({'tag':tag_dic.keys(),'number':tag_dic.values()})
    print(tag_df)
    fig = px.histogram(tag_df, x="tag", y="number")
  elif mode == "file":
    file_df = pd.DataFrame.from_dict({'filename':file_dic.keys(),'number':file_dic.values()})
    print(file_df)
    fig = px.histogram(file_df, x="filename", y="number") 
  elif mode == "time":
    time_df = pd.DataFrame.from_dict({'timestamp':time_dic.keys(),'number':time_dic.values()})
    print(time_df)
    fig = px.line(
      time_df, 
      x="timestamp", y="number")
  else:
    print_util()

  fig.update_layout(autosize=False, width=900)
  fig.show()


