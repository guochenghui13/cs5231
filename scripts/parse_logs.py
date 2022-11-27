import json
import collections
import sys

from parse_rules import *

class LogItem:
  def __init__(self, rule_type = None, log = []) -> None:
    self.rule_type = rule_type
    self.log = log
  
  def add_log(self, log):
    self.log = log

  def __str__(self) -> str:
    return "rule_type: " + self.rule_type.__str__() + '\n' + 'log: ' + self.log.__str__()

def parse(filename):
    f = open(filename)
    # save filtered logs to another ndjson file for reference.
    output= open(".."+filename.split('.')[2]+"_filtered.ndjson", "w")
    
    fd_map = {"0": "STDIN_FILENO", "1": "STDOUT_FILENO", "2": "STDERR_FILENO"}
    fd_count = {}
    
    accessed_file = ''
    
    program_activities = {}
    
    events = {}
    
    for log in f.readlines():
        data = json.loads(log)

        try:
            timestamp = data['@timestamp']
            seq = int(data['auditd']['sequence'])
            tag = data['tags'][0]
        except KeyError as e:
            continue
        
        syscall = ''
        # use tag to find matching rule type
        rule_type = CatchRules().search_rule(tag)
        if tag == 'sys_access':
            try:
                syscall = data['auditd']['data']['syscall']
                process_name = data['process']['name']
                process_executable = data['process']['executable']
            except KeyError as e:
                continue
            if syscall == 'read' or syscall == 'write' or syscall == 'writev':
                try:
                    a0 = data['auditd']['data']['a0']
                    accessed_file = fd_map.get(a0, "unknown")
                except KeyError as e:
                    continue
            elif syscall == 'open' or syscall == 'openat':
                try:
                    file_path = data['file']['path']
                    exit = data['auditd']['data']['exit']
                except KeyError as e:
                    continue
                fd_map[exit] = file_path
                accessed_file = file_path
                
            if (accessed_file.startswith("/home/student/secret/") or "program" in process_executable):
                output.write(log)
                events[seq] = LogItem(rule_type = rule_type, log=(timestamp, syscall, process_executable, accessed_file))
                if process_executable in program_activities:
                    program_activities[process_executable].append([seq, timestamp, syscall, accessed_file])
                else:
                    program_activities[process_executable]= [[seq, timestamp, syscall, accessed_file]]
        if tag == 'sys_exe':
            try:
                syscall = data['auditd']['data']['syscall']
                process_name = data['process']['name']
                process_executable = data['process']['executable']
            except KeyError as e:
                continue
            if syscall == 'execve':
                try:
                    process_args = data['process']['args']
                except KeyError as e:
                    continue
                output.write(log)
                events[seq] = LogItem(rule_type = rule_type, log=(timestamp, syscall, process_executable, process_args))
                if process_executable in program_activities:
                    program_activities[process_executable].append([seq, timestamp, syscall, process_args])
                else:
                    program_activities[process_executable] = [[seq, timestamp, syscall, process_args]]

    od = collections.OrderedDict(sorted(events.items()))
    
    # print by sequence order
    for idx, e in enumerate(od):
        print(idx, e, od[e])
   
    print('\n')  
    print('\n') 
    print('\n') 
    
    # print by program activities
    # for key, values in program_activities.items():
    #     print(key, ':')
    #     for i in values:
    #         print('\t', i)
    
    # output.close()
    # f.close()

parse("../logs/auditbeat-20221126.ndjson")