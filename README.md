
# 🔐 Investigate Brute Force in Splunk

## 📌 Introduction

This project demonstrates how Splunk Enterprise Platform can be used to investigate a simulated Windows authentication incident involving repeated failed login attempts and a suspected account compromise.

Working from the perspective of a junior Security Operations Center (SOC) analyst, the investigation uses a synthetic dataset containing 15 Windows authentication events. Search Processing Language (SPL) is used to identify accounts with unusually high numbers of failed logins, investigate suspicious authentication sequences, and distinguish legitimate service activity from potentially malicious behavior.

The investigation focuses on correlating Windows Event ID 4625 (failed logon) with Event ID 4624 (successful logon). Rather than relying on failed login counts alone, the analysis examines the order and context of authentication events to determine which activity warrants escalation.

The project concludes with a private SOC Authentication Investigation dashboard, and a documented incident report.

## 🛠️ Technologies Used

| Technology                       | Purpose                                                                         |
| -------------------------------- | ------------------------------------------------------------------------------- |
| Splunk Enterprise Platform       | SIEM platform for ingesting, searching, and investigating authentication events |
| Search Processing Language (SPL) | Query language used to filter, aggregate, and correlate authentication activity |
| Microsoft Edge                   | Accessing the Splunk Enterprise environment                                     |
| Windows Notepad                  | Creating the synthetic authentication dataset and documentation files           |
| CSV                              | Structured format for storing the synthetic Windows authentication events       |
| Markdown                         | Documenting investigation queries and the final incident report                 |
| Windows Authentication Events    | Event IDs 4624 and 4625 used to investigate successful and failed logons        |
| Splunk Dashboards                | Visualizing authentication candidates and the suspicious login timeline         |

## ⚙️ Features

- **Synthetic Authentication Dataset:** Creates a controlled dataset containing 15 Windows authentication events.
- **SIEM Data Ingestion:** Uploads and indexes the CSV dataset in Splunk Enterprise.
- **Authentication Event Analysis:** Examines failed and successful Windows logon events.
- **Threshold-Based Detection:** Identifies accounts and source IP combinations with at least five failed login attempts.
- **Candidate Triage:** Separates high-failure authentication activity into candidates requiring further investigation.
- **Event Correlation:** Compares failed and successful logons to identify suspicious authentication sequences.
- **Timeline Investigation:** Reconstructs authentication activity in timestamp order.
- **False-Positive Analysis:** Distinguishes expected backup-service activity from a potentially compromised account.
- **Security Dashboard:** Displays high-failure candidates and their supporting authentication evidence.
- **Incident Documentation:** Preserves investigation queries, findings, severity, and response recommendations in Markdown.
- **Tuned Detection Rule:** Combines failed and successful login conditions to identify higher-confidence compromise candidates.

## 🎯 What This Project Demonstrates

This project demonstrates foundational SOC analysis and detection engineering skills, including:

- SIEM data ingestion and field extraction.
- Windows authentication log analysis.
- Investigation of Event IDs 4624 and 4625.
- SPL query development and statistical aggregation.
- Threshold-based security detection.
- Event correlation and timeline reconstruction.
- Identification of suspicious authentication patterns.
- False-positive identification and reduction.
- Detection logic refinement.
- Security dashboard development.
- Incident severity classification.
- Incident reporting and evidence preservation.
- Development of repeatable security investigation workflows.


## 🔄 The Process

The investigation followed a structured SOC workflow, beginning with synthetic data creation and ingestion before progressing into authentication analysis, event correlation, dashboard development, and incident reporting.

### 1. 📥 Set Up the SOC Investigation Environment

The first step was establishing a controlled environment for investigating Windows authentication activity.

A synthetic CSV dataset was created using Windows Notepad and saved as `soc_windows_auth.csv`.

The dataset contains 15 authentication events with fixed timestamps and the following fields:

| Field       | Description                                  |
| ----------- | -------------------------------------------- |
| timestamp   | Date and time of the authentication event    |
| event_id    | Windows authentication event identifier      |
| user        | Account associated with the event            |
| source_ip   | IP address associated with the login attempt |
| status      | Authentication outcome                       |
| logon_type  | Type of Windows logon                        |
| destination | Target system involved in the authentication |
| context     | Additional information describing the event  |

Two Windows event IDs were central to the investigation:

- **Event ID 4625:** Records a failed logon attempt.
- **Event ID 4624:** Records a successful logon.

The CSV file was uploaded into Splunk Cloud Platform using the Add Data wizard. The source type was identified as CSV, and the index was left at its default setting.

After ingestion, the All Time search range was selected to ensure all synthetic events were available for analysis.

The following SPL search was used to verify successful ingestion:

```
source="soc_windows_auth.csv"
| stats count
```

The Statistics tab returned a total of 15 events, confirming that all authentication records were searchable.

The extracted fields were also reviewed to ensure the dataset contained the information needed for the investigation.

<img width="975" height="266" alt="image" src="https://github.com/user-attachments/assets/f16a22e8-c673-43f9-96b9-533f5ee1dbec" />


### 2. 🔎 Identify High-Failure Login Candidates

With the dataset available in Splunk, the next step was identifying accounts associated with repeated failed authentication attempts.

A baseline search was first performed to review all 15 events and verify the available fields.

```
source="soc_windows_auth.csv"
| table timestamp event_id user source_ip status logon_type destination context
```

The table command organized the authentication records into a consistent format, making it easier to compare individual events.

**Run the failure threshold**

A threshold-based search was then used to identify user and source IP combinations associated with at least five failed login attempts.

```
source="soc_windows_auth.csv" event_id=4625
| stats count AS failed_logons BY user source_ip
| where failed_logons>=5
| sort - failed_logons
```

This search performs several operations:

- Filters the dataset for Event ID 4625, representing failed logons.
- Groups events by username and source IP address.
- Counts failed attempts for each combination.
- Retains candidates with five or more failures.
- Sorts the results from highest to lowest failure count.

**Investigation results**

Two candidates were identified:

| User       | Source IP    | Failed Logons | Initial Classification |
| ---------- | ------------ | ------------- | ---------------------- |
| alex       | 203.0.113.77 | 6             | Unresolved             |
| backup_svc | 192.0.2.10   | 5             | Unresolved             |

Both candidates exceeded the configured threshold.

However, the threshold alone could not determine whether either account had been compromised. Repeated failures can also result from legitimate activity, such as an incorrectly configured service repeatedly attempting authentication.

Both candidates were therefore retained for further investigation rather than immediately classified as malicious.
<img width="975" height="164" alt="image" src="https://github.com/user-attachments/assets/42ca3fce-706f-416f-af2f-464bfc7d9076" />


### 3. 🕵️ Correlate Authentication Events

The next phase examined the chronological sequence of authentication events to determine whether the repeated failures were followed by successful access.

This step was important because a successful logon following repeated failures can indicate that an attacker eventually obtained access to an account.

**Investigate backup_svc**

The first timeline search focused on the backup service account.

```
source="soc_windows_auth.csv" source_ip="192.0.2.10" user="backup_svc" (event_id=4624 OR event_id=4625)
| sort 0 timestamp
| table timestamp event_id user source_ip status logon_type destination context
```

The search isolated authentication events associated with `backup_svc` and its source IP address.

The results were sorted chronologically to determine whether any successful authentication occurred after the failed attempts.

**Findings:**

- Five failed authentication events were identified.
- All events contained `approved_backup_service` context.
- No successful Event ID 4624 logon followed the failures.

The results were consistent with expected backup-service activity rather than a confirmed account compromise.

The candidate was classified as an expected-service false positive requiring detection tuning.

<img width="975" height="227" alt="image" src="https://github.com/user-attachments/assets/61b5e901-07b0-4892-b3aa-d2090f8e8653" />


**Investigate alex**

The second timeline search focused on the suspicious account and source IP identified during the threshold investigation.

```
source="soc_windows_auth.csv" source_ip="203.0.113.77" user="alex" (event_id=4624 OR event_id=4625)
| sort 0 timestamp
| table timestamp event_id user source_ip status logon_type destination context
```

This search isolated authentication activity associated with `alex` and displayed both failed and successful logons in timestamp order.

**Findings:**

The investigation returned seven authentication events:

| Timestamp (UTC)     | Event ID | Authentication Result |
| ------------------- | -------- | --------------------- |
| 2026-08-30 09:00:00 | 4625     | Failed                |
| 2026-08-30 09:00:30 | 4625     | Failed                |
| 2026-08-30 09:01:00 | 4625     | Failed                |
| 2026-08-30 09:01:30 | 4625     | Failed                |
| 2026-08-30 09:02:00 | 4625     | Failed                |
| 2026-08-30 09:02:30 | 4625     | Failed                |
| 2026-08-30 09:03:00 | 4624     | Successful            |

Additional observations:

- All seven events originated from `203.0.113.77`.
- All events targeted the `alex` account.
- The successful authentication occurred immediately after six consecutive failures.
- All events used logon type 3, indicating network logons.
- The events involved `FILE-SRV-01`.
- The context was identified as `external_unknown`.

The transition from repeated failures to successful authentication provided stronger evidence of a potential brute-force account compromise.

<img width="975" height="287" alt="image" src="https://github.com/user-attachments/assets/5fd2f2ea-a24f-406a-a1dc-6a7527d8dff8" />


**Determine the investigation verdicts**

After examining both timelines, the candidates were classified as follows:

| Candidate               | Evidence                                                              | Classification                                        |
| ----------------------- | --------------------------------------------------------------------- | ----------------------------------------------------- |
| backup_svc — 192.0.2.10 | Five failures, approved backup-service context, no subsequent success | Expected-service false positive; requires tuning      |
| alex — 203.0.113.77     | Six consecutive failures followed by a successful network logon       | Likely true positive for suspected account compromise |

The investigation identified `alex` as the primary account requiring escalation.

The findings demonstrate why authentication events must be examined in context. A high number of failures alone is insufficient to establish that an account has been compromised.

### 4. 📊 Build the SOC Authentication Investigation Dashboard

After completing the authentication analysis, the investigation results were organized into a private Splunk dashboard.

The dashboard was designed to present the initial detection signal alongside the chronological evidence used to classify the suspicious activity.

**Panel 1: High-Failure Candidates**

Visualization: Table

```
source="soc_windows_auth.csv" event_id=4625
| stats count AS failed_logons BY user source_ip
| where failed_logons>=5
| sort - failed_logons
```

Displays accounts and source IP addresses that exceed the failed login threshold.

The panel preserves both candidates identified during the initial triage process.

**Panel 2: Suspicious Login Timeline**

Visualization: Table

```
source="soc_windows_auth.csv" source_ip="203.0.113.77" user="alex" (event_id=4624 OR event_id=4625)
| sort 0 timestamp
| table timestamp event_id user source_ip status logon_type destination context
```

Displays the chronological authentication sequence associated with the suspicious account.

The panel provides the supporting evidence behind the investigation verdict.

**Dashboard configuration**

The dashboard was created with the title:

`SOC Authentication Investigation`

Dashboard permissions were kept at Private.

The panels were arranged in investigation order:

1. High-Failure Candidates.
2. Suspicious Login Timeline.

This arrangement allows a reviewer to first identify the accounts that triggered the threshold and then examine the event sequence that supports the final classification.

<img width="975" height="401" alt="image" src="https://github.com/user-attachments/assets/71f50bfd-3d97-47d0-80d7-a1ef3db32dfb" />


### 5. 📝 Document the Investigation and Incident Report

The final investigation phase involved preserving the SPL searches and documenting the findings in standalone Markdown files.

Two files were created using Windows Notepad.

**File 1: `soc_investigation_queries.md`**

This file preserves the searches used throughout the investigation.

The documented searches include:

1. Baseline Authentication Events
2. High-Failure Candidate Detection
3. Backup Service Authentication Timeline
4. Suspicious Account Authentication Timeline

The query file provides a reusable reference for reproducing the investigation and reviewing the detection logic.

**File 2: `incident_report.md`**

A separate incident report was created to document the case findings and communicate the investigation outcome.

The report identifies the case as:

| Field             | Value                                    |
| ----------------- | ---------------------------------------- |
| Incident ID       | SOC-001                                  |
| Account           | alex                                     |
| Source IP         | 203.0.113.77                             |
| Target System     | FILE-SRV-01                              |
| Failed Logons     | 6                                        |
| Successful Logons | 1                                        |
| Event Sequence    | 4625 followed by 4624                    |
| Severity          | High                                     |
| Classification    | Likely True Positive                     |
| Assessment        | Suspected Brute-Force Account Compromise |

The incident report also documents the authentication timeline, supporting evidence, assessment, and recommended response actions.

**Response recommendations**

The report includes recommendations covering:

- **Containment:** Restrict suspicious access and secure the affected account.
- **Evidence Preservation:** Retain relevant authentication logs, timestamps, and investigation results.
- **Investigation:** Examine the affected account and destination system for additional suspicious activity.
- **Source Monitoring:** Monitor the suspicious source IP and related authentication attempts.
- **Recovery:** Reset compromised credentials where appropriate, review access permissions, and restore normal operations after validation.

The completed files were reopened to verify that the investigation queries and incident report remained accessible and properly formatted.

## 📚 What I Learned

This project provided practical experience investigating authentication activity and distinguishing suspicious login patterns from expected operational behavior.

Key takeaways included:

- **Windows Authentication Events:** Learned how Event IDs 4624 and 4625 represent successful and failed logon activity.
- **Threshold-Based Detection:** Gained experience using SPL to identify accounts with unusually high numbers of failed authentication attempts.
- **Event Correlation:** Learned why failed login counts should be correlated with successful authentication events before determining whether an account may be compromised.
- **Timeline Analysis:** Developed an understanding of how chronological event sequences can reveal patterns hidden by aggregated statistics.
- **False-Positive Reduction:** Learned how expected service activity can trigger detection thresholds and why additional context is necessary to classify alerts accurately.
- **Detection Engineering:** Explored how combining multiple authentication conditions can improve detection precision.
- **Incident Documentation:** Gained experience translating technical search results into an incident report with supporting evidence and response recommendations.
- **Security Dashboards:** Learned how to organize investigation results into a dashboard that communicates the progression from initial detection to final assessment.

One of the most important lessons was that a failed login threshold is a starting point for investigation, not a definitive indicator of compromise.

Correlating failed and successful logons provided the additional evidence needed to distinguish the two candidates.

## 🚀 How It Can Be Improved

The investigation provides a foundation for authentication monitoring and brute-force detection. Several enhancements could expand its functionality.

- **Scheduled Detection Alerts:** Configure scheduled Splunk alerts to identify authentication patterns that meet the tuned correlation criteria.
- **Real-Time Monitoring:** Replace the synthetic dataset with live Windows Security Event Logs from a controlled lab environment.
- **Time-Based Thresholds:** Introduce time-window restrictions so repeated failures within a short period receive greater investigative priority.
- **Additional Authentication Fields:** Incorporate logon process, authentication package, workstation name, and failure reason to provide more context.
- **Account Risk Analysis:** Compare authentication patterns across privileged accounts, service accounts, and standard user accounts.
- **Threat Intelligence Enrichment:** Integrate IP reputation data to provide additional context for suspicious authentication sources.
- **SOAR Integration:** Connect detection results to an automation platform such as n8n to support ticket creation, enrichment, and analyst notifications.
- **Expanded Dashboard:** Add authentication trend charts, account-level filters, source IP summaries, and detection status indicators.
- **Advanced Correlation:** Expand the detection logic to identify repeated failures followed by successful access across multiple accounts and systems.

These enhancements could help transform the controlled investigation into a more comprehensive authentication monitoring and detection workflow.

## 🏁 Project Complete

The investigation demonstrates how Splunk can be used to move beyond basic failed-login detection and perform evidence-based authentication analysis.

By correlating failed and successful logons, the investigation distinguishes expected service activity from a suspicious account-compromise sequence while preserving the findings in a reusable dashboard and incident report.

