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
    output= open(".."+filename.split('.')[2]+"_filtered.json", "w")

    # parsed rules from ../rules/example.rules
    rule_types = CatchRules()
    
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
        rule_type = rule_types.search_rule(tag)[0]
        log_json = {}
        log_item = None
        try:
            syscall = data['auditd']['data']['syscall']
            process_name = data['process']['name']
            process_executable = data['process']['executable']
            pid = data['process']['pid']
            user = data['user']['group']
            log_json = {
                "timestamp" : timestamp,
                "syscall" : syscall, 
                "executable" : process_executable, 
                "pid" : str(pid), 
                "user" : user
            }
        except KeyError as e:
            print(e)
            continue

        if rule_type.type == 'syscall':
            
            if tag == 'sys_access':
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
                    log_json["accessed_file"] = accessed_file
            
            if tag == 'sys_exe':
                if syscall == 'execve':
                    try:
                        process_args = data['process']['args']
                    except KeyError as e:
                        continue
                    # output.write(log)
                    log_json["args"] = str(process_args).replace('\\\\', '\\')
                    # events[seq] = LogItem(rule_type = rule_type, log=json.dumps(log_json))
            
            if tag == 'sys_curl' or tag == 'power_abuse':
                if syscall == 'openat' or syscall == 'open':
                    try:
                        paths = data['auditd']['paths']
                        file_path = data['file']['path']
                        exit = data['auditd']['data']['exit']
                    except KeyError as e:
                        continue

                    fd_map[exit] = file_path

                    if len(paths) > 1:
                        name_type = paths[1]['nametype']
                        name = data['auditd']['paths'][1]['name']
                    
                    if name_type == 'CREATE':
                        log_json["accessed_file"] = file_path
                        log_json["name_type"] = name_type
                        log_json["name"] = name
               
            if syscall == 'connect':
                try:
                    dest = data['destination']['path']
                    socket = data['auditd']['data']['socket']
                    result = data['auditd']['result']
                except KeyError as e:
                    continue
                log_json["destination"] = dest
                log_json["socket"] = str(socket)
                log_json["result"] = result
            
            if tag == 'socket_as_server':
                if syscall == 'bind':
                    try:
                        dest = data['destination']['path']
                        socket = data['auditd']['data']['socket']
                        result = data['auditd']['result']
                        a0 = data['auditd']['data']['a0']
                    except KeyError as e:
                        continue
                    
                    accessed_file = fd_map.get(a0, "unknown")
                    
                    log_json["destination"] = dest
                    log_json["socket"] = str(socket)
                    log_json["result"] = result
                    log_json["accessed_file"] = accessed_file
                
                elif syscall == 'accept':
                    try:    
                        result = data['auditd']['result']
                        a0 = data['auditd']['data']['a0']
                    except KeyError as e:
                        continue
                    
                    accessed_file = fd_map.get(a0, "unknown")

                    log_json["result"] = result
                    log_json["accessed_file"] = accessed_file
            
            if tag.startswith("socket_create"):
                try:    
                    result = data['auditd']['result']
                    a0 = data['auditd']['data']['a0']
                    exit = data['auditd']['data']['exit']
                except KeyError as e:
                    continue
                    
                accessed_file = fd_map.get(a0, "unknown")
                log_json["result"] = result
                log_json["accessed_file"] = accessed_file
                log_json["exit"] = exit
        else:
            pass
        log_item = LogItem(rule_type = rule_type, log=json.dumps(log_json))
        events[seq] = log_item
        # write all the parsed logs as json
        output.write(json.dumps({'sequence':seq, 'rule':str(rule_type), 'log':json.dumps(log_json)}))
        output.write('\n')

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
        log = json.loads(od[e].log)
        print(log)
        process_executable = log["executable"]
        if process_executable in program_activities:
            program_activities[process_executable].append([e, od[e]])
        else:
            program_activities[process_executable]= [[e, od[e]]]
    
    for key, values in program_activities.items():
        print(key, ':')
        for i in values:
            print('\t', "sequence=", i[0], i[1])
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


parse("../logs/auditbeat-20221127.ndjson", "program")