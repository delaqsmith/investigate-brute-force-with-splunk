# SOC Authentication Investigation Queries

## 1. Baseline event table

```spl
source="soc_windows_auth.csv"
| table timestamp event_id user source_ip status logon_type destination context
```

## 2. High-failure candidates

```spl
source="soc_windows_auth.csv" event_id=4625
| stats count AS failed_logons BY user source_ip
| where failed_logons>=5
| sort - failed_logons
```
## 3. Backup-service timeline

```spl
source="soc_windows_auth.csv" source_ip="192.0.2.10" user="backup_svc" (event_id=4624 OR event_id=4625)
| sort 0 timestamp
| table timestamp event_id user source_ip status logon_type destination context
```

## 4. Suspicious-source timeline

```spl
source="soc_windows_auth.csv" source_ip="203.0.113.77" user="alex" (event_id=4624 OR event_id=4625)
| sort 0 timestamp
| table timestamp event_id user source_ip status logon_type destination context
```
## 5. Tuned correlation rule

```spl
source="soc_windows_auth.csv" (event_id=4624 OR event_id=4625)
| stats count(eval(event_id=4625)) AS failed_logons count(eval(event_id=4624)) AS successful_logons BY user source_ip
| where failed_logons>=5 AND successful_logons>=1
| sort - failed_logons
```