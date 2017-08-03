# sysmon2neo4j

### Usage ###
This script makes use of logstash's "pipe" output plugin.  Events are piped from logstash to sysmon2neo4j.py via stdin.

Modify the script to include the username and password of your Neo4j instance.

Edit your logstash pipeline to look something like this:

```
output {
	if [source_name] == "log_name":"Microsoft-Windows-Sysmon/Operational" {
		pipe {
			ttl => 300
			codec => 'json'
			command => 'python /path/to/sysmon2neo4j.py'
		}
	}
}
```