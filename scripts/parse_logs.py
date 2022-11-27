import json
import collections
import sys
import re

from parse_rules import *

class LogItem:
  def __init__(self, rule_type = None, log = []) -> None:
    self.rule_type = rule_type
    self.log = log
  
  def add_log(self, log):
    self.log = log

  def __str__(self) -> str:
    return "rule_type: " + self.rule_type.__str__() + '\n' + 'log: ' + self.log.__str__()

def parse(filename, print_style = ""):
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
        rule_type = CatchRules().search_rule(tag)[0]
        if tag == 'sys_access':
            try:
                syscall = data['auditd']['data']['syscall']
                process_name = data['process']['name']
                process_executable = data['process']['executable']
                pid = data['process']['pid']
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

            if (accessed_file.startswith("/home/student") or "program" in process_executable):
                output.write(log)
                log_content = (timestamp, "syscall="+syscall, "executable="+process_executable, "pid="+str(pid), "accessed_file="+accessed_file)
                events[seq] = LogItem(rule_type = rule_type, log=log_content)
        if tag == 'sys_exe':
            try:
                syscall = data['auditd']['data']['syscall']
                process_name = data['process']['name']
                process_executable = data['process']['executable']
                pid = data['process']['pid']
            except KeyError as e:
                continue
            if syscall == 'execve':
                try:
                    process_args = data['process']['args']
                except KeyError as e:
                    continue
                output.write(log)
                log_content = (timestamp, "syscall="+syscall, "executable="+process_executable,"pid="+str(pid), "args="+str(process_args))
                events[seq] = LogItem(rule_type = rule_type, log=log_content)
        
        if tag == 'sys_curl' or tag == 'power_abuse':
            try:
                syscall = data['auditd']['data']['syscall']
                process_executable = data['process']['executable']
                pid = data['process']['pid']
            except KeyError as e:
                continue

            if syscall == 'openat' or syscall == 'open':
                try:
                    paths = data['auditd']['paths']
                    file_path = data['file']['path']
                except KeyError as e:
                    continue

                if len(paths) > 1:
                    name_type = paths[1]['nametype']
                    name = data['auditd']['paths'][1]['name']
                
                if name_type == 'CREATE':
                    output.write(log)
                    log_content = (timestamp, "syscall="+syscall, "executable="+process_executable, "pid="+str(pid), "accessed_file="+file_path, "name_type="+name_type, "name="+name)
                    events[seq] = LogItem(rule_type = rule_type, log=log_content)
            if syscall == 'connect':
                try:
                    dest = data['destination']['path']
                    socket = data['auditd']['data']['socket']
                    result = data['auditd']['result']
                except KeyError as e:
                    continue
                output.write(log)
                log_content = (timestamp, "syscall="+syscall, "executable="+process_executable, "pid="+str(pid), "destination="+dest, "socket="+str(socket), "result="+result)
                events[seq] = LogItem(rule_type = rule_type, log=log_content)

    od = collections.OrderedDict(sorted(events.items()))
    
    if print_style == "normal" or print_style == "":
        print_events(od)
    elif print_style == "pid" :
        pid_dict = group_by_pid(od)
    elif print_style == "program":   
        program_activities = group_by_program(od)
    
    output.close()
    f.close()

def print_events(od):
    for idx, e in enumerate(od):
        print(idx, e, od[e])
        print('---')

def group_by_program(od):
    program_activities = {}
    for idx, e in enumerate(od):
        process_executable = od[e].log[2].split('=')[1]
        if process_executable in program_activities:
            program_activities[process_executable].append([e, od[e].log])
        else:
            program_activities[process_executable]= [[e, od[e].log]]
    
    for key, values in program_activities.items():
        print(key, ':')
        for i in values:
            print('\t', "sequence=", i[0], "log=", i[1])
    return program_activities

def group_by_pid(od):
    pid_dict = {}
    for idx, e in enumerate(od):
        pid=od[e].log[3].split('=')[1]
        if pid in pid_dict:
            pid_dict[pid].append([e, od[e]])
        else:
            pid_dict[pid] = [[e, od[e]]]

    for key, values in pid_dict.items():
        print("pid=", key, ':')
        for i in values:
            print('\t', "sequence=", i[0], "log=", i[1].log)
    return pid_dict


parse("../logs/auditbeat-20221127.ndjson", "pid")