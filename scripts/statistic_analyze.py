from parse_rules import *
from parse_logs import log_file
import json
import sys
import os
import pandas as pd
import plotly.express as px

# log_file = "../logs/auditbeat-20221131.ndjson"
current_path = os.path.dirname(__file__)
parsed_log_file = os.path.join(
  current_path, 
  "..", 
  os.path.dirname(log_file).split('/')[1], 
  os.path.basename(log_file).split('.')[0]+"_filtered.json"
)

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
        # print('passed',log)
        pass

      line = f.readline()

def folder_map(filename):
  paths = filename.split('/')
  folder = '/'.join(paths[:-1])
  if (folder == ''):
    folder = 'unknown'
  return folder

def print_util():
  print("Please indicate a statistic graph to see, default: time")
  print("Available options: time, tag, file, folder")

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print_util()
    exit()
  
  collect_statistic(parsed_log_file, time_dic, tag_dic, file_dic)
  mode = sys.argv[1]

  if mode == "tag":
    tag_df = pd.DataFrame.from_dict({'tag':tag_dic.keys(),'number':tag_dic.values()})
    tag_df = tag_df.sort_values(by=['number'], ascending=False)
    print(tag_df)
    fig = px.histogram(tag_df, x="tag", y="number")
    fig.update_layout(autosize=False, width=1000)
    fig.update_layout(title_text="Number of Tags",title_x=0.5)
  
  elif mode == "file" or mode == "folder":
    file_df = pd.DataFrame.from_dict({'filename':file_dic.keys(),'number':file_dic.values()})
    if mode == "file":
      file_df = file_df.sort_values(by=['number'], ascending=False)
      print(file_df)
      fig = px.histogram(file_df, x="filename", y="number") 
      fig.update_layout(title_text="Number of File Access",title_x=0.5)
      fig.update_layout(width=2000)
    else:
      file_df['folder'] = file_df.apply (lambda row: folder_map(row['filename']), axis=1)
      file_df = file_df.groupby('folder').sum()
      file_df = file_df.sort_values(by=['number'], ascending=False)
      print(file_df)
      fig = px.histogram(file_df, x=file_df.index, y="number") 
      fig.update_layout(title_text="Number of File Access in Folder",title_x=0.5)
  
  elif mode == "time":
    time_df = pd.DataFrame.from_dict({'timestamp':time_dic.keys(),'number':time_dic.values()})
    print(time_df)
    fig = px.line(
      time_df, 
      x="timestamp", y="number")
    fig.update_layout(title_text="Number of Logs During Time",title_x=0.5)
  else:
    print_util()

  fig.show()
