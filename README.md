# Compliance Readiness Command Center

## Executive summary
Production-style Next.js portfolio app for multi-framework readiness across SOC 2, HIPAA, PCI DSS, NIST RMF, and NIST 800-53 using synthetic data.

## Problem statement
Startups run fragmented compliance programs. This project centralizes controls, evidence, risks, remediation, and executive reporting.

## Why this project matters
It demonstrates TPM + GRC operating model execution with reusable controls and auditor-ready outputs.

## Supported frameworks
SOC 2, HIPAA Security Rule, PCI DSS, NIST RMF, NIST SP 800-53.

## Key features
Dashboard, control library, crosswalk mapping/export, evidence package export, risk register, remediation tracker, framework modules, audit trail, reports.

## Architecture overview
Next.js App Router + TypeScript + Tailwind + Prisma schema + SQLite local development.

## Data model overview
User, Framework, Control, ControlMapping, Evidence, Risk, Remediation, AuditEvent, Milestone, SystemAsset, Department, Report.

## Screenshots
Add screenshots here after running locally.

## Run locally
1. npm install
2. npx prisma generate
3. npm run dev

## Seed data
Synthetic demo-safe dataset in `lib/data.ts` with 55 controls, 24 evidence records, 18 risks, 22 remediations.

## Demo workflow (BayCloud Analytics)
1) Executive checks dashboard 2) TPM reviews readiness 3) GRC lead identifies PCI segmentation gap 4) Engineering updates remediation 5) Compliance manager exports SOC2 evidence package 6) Executive reviews 30/60/90 plan 7) Auditor reviews audit trail.

## Security and privacy notes
No real PHI/payment/company secrets. Synthetic metadata only.

## Limitations
Mock auth and metadata-based evidence upload placeholders.

## Future enhancements
Cloud evidence collectors, Jira/GitHub/Slack integrations, Okta imports, policy/vendor modules, CCM, RBAC, PDF package generation, AI summary option.

## Resume bullets
Built multi-framework compliance readiness platform mapping SOC 2, HIPAA, PCI DSS, NIST RMF, and NIST 800-53 controls to evidence, owners, risk ratings, and remediation workflows | Enabled executive visibility into audit readiness, control gaps, and cross-framework compliance status through centralized dashboards and automated reporting
- Developed GRC command center for SaaS compliance readiness, integrating control mapping, evidence tracking, risk scoring, remediation workflows, audit trails, and executive reporting across five major security frameworks
- Designed cross-framework control mapping engine to reduce duplicate compliance effort by linking reusable evidence across SOC 2, HIPAA, PCI DSS, NIST RMF, and NIST 800-53 requirements
- Created TPM-style remediation workflow with owner accountability, due dates, blockers, program RAG status, and 30/60/90 day roadmap reporting for audit readiness initiatives
- Built synthetic, demo-safe compliance dataset with 50+ controls, 20+ evidence records, 15+ risks, 20+ remediation tasks, framework readiness scoring, and exportable audit packages

## Interview talking points
1. “I built this to show how a TPM can turn compliance from a static checklist into an operating model with owners, evidence, risk, deadlines, and executive visibility.”
2. “The main design decision was to avoid treating SOC 2, HIPAA, PCI, and NIST as separate programs. Instead, I created a reusable control layer that maps one control to multiple obligations.”
3. “The evidence package feature demonstrates how audit readiness depends on both control implementation and evidence freshness.”
4. “The remediation tracker reflects how real compliance programs fail: not because teams lack controls, but because ownership, deadlines, dependencies, and escalation paths are unclear.”
5. “This project is demo-safe and uses synthetic data, but the workflows mirror real SaaS, healthtech, fintech, and regulated cloud environments.”
