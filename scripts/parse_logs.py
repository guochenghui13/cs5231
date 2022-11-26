import json
import collections
import sys

from parse_rules import RuleType

class LogItem:
  def __init__(self, rule_type, log = "") -> None:
    self.rule_type = rule_type
    self.log = log

def parse(filename):
    f = open(filename)
    # save filtered logs to another ndjson file for reference.
    output= open(filename.split('.')[0]+"_filtered.ndjson", "w")
    
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
        if tag == 'student_syscall':
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
        

        if(accessed_file.startswith("/home/student/secret/")
           or "program" in process_executable):
            output.write(log)
            events[seq] = (timestamp, syscall, process_executable, accessed_file)
            if process_executable in program_activities:
                program_activities[process_executable].append([seq, timestamp, syscall, accessed_file])
            else:
                program_activities[process_executable]= [[seq, timestamp, syscall, accessed_file]]

    od = collections.OrderedDict(sorted(events.items()))
    
    # print by sequence order
    for idx, e in enumerate(od):
        print(idx, e, od[e])
   
    print('\n')  
    print('\n') 
    print('\n') 
    
    # print by program activities
    for key, values in program_activities.items():
        print(key, ':')
        for i in values:
            print('\t', i)
    
    output.close()
    f.close()

parse("../auditbeat-20221125.ndjson")