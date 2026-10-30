# Incident Report: SOC-001

Analyst: Dela Smith
Date investigated: 2026-08-30
Status: Escalate for containment and deeper investigation
Classification: Likely true positive - suspected brute-force account compromise
Severity: High

## Executive Summary

Splunk analysis identified six failed network logons for the account `alex` from `203.0.113.77`, followed by one successful network logon from the same source. The sequence is consistent with a likely brute-force attempt that obtained valid access. A second high-failure candidate, `backup_svc` from `192.0.2.10`, had five failures but no successful logon and was classified as an expected-service false positive for this exercise.

## Evidence

- Destination: `FILE-SRV-01`
- Account: `alex`
- Source: `203.0.113.77`
- Window: `2026-08-30T09:00:00Z` to `2026-08-30T09:03:00Z`
- Failed logons: `6` events with event ID `4625`
- Successful logons: `1` event with event ID `4624`
- Logon type: `3`, network logon

## Analyst Assessment

The failed-logon threshold initially returned two candidates, which showed that failure counts alone were not sufficient for classification. Timeline correlation isolated the stronger risk pattern for `alex`: repeated failures followed by a success from the same source. The backup-service activity lacked a successful logon and had approved-service context, so it should be tuned rather than escalated.

## Recommended Response

1. Contain access by disabling or resetting the affected account according to organizational procedure.
2. Preserve the authentication evidence and collect relevant endpoint and server logs around the incident window.
3. Investigate activity performed by `alex` after the successful logon and search for the same source across other accounts.
4. Block or monitor the source according to organizational policy and validate recovery before restoring normal access.

## Portfolio Summary

This investigation demonstrates SIEM ingestion, SPL searching, threshold detection, event correlation, false-positive analysis, dashboard creation, and incident reporting.