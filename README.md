# sysmon2neo4j

### Usage ###
This script makes use of logstash's "pipe" output plugin.  Events are piped from logstash to sysmon2neo4j.py via stdin.

Edit your logstash pipeline to look something like this:

```
pipe {
		ttl => 300
		codec => 'json'
		command => 'python /path/to/sysmon2neo4j.py'
	}
```
