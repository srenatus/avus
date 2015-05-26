#!/usr/bin/awk -f

# new header
BEGIN {
      print "vuln_id,name,garbage,cwe_name,cwe_id,severity,file,path,parameter,line_no"
      }

# ignore informational output, old header
!/^INFO|^Generic|^Scanner/
