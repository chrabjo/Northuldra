Northuldra

Northuldra™ name and branding are not licensed for reuse without permission.

Northuldra is an experimental SOC lab simulation toolkit built to generate realistic security telemetry through recon-focused orchestration. The goal of this project is not exploitation, but controlled activity that helps analysts test detection workflows, automation pipelines, and AI-assisted SOC analysis.

This project reflects my ongoing work exploring how automation and AI-assisted development can enhance cybersecurity training, detection engineering, and hands-on learning environments.

Rather than acting as a traditional pentesting framework, Northuldra functions as a purple-team simulation layer — coordinating commonly used security tools to produce structured outputs that can be analyzed by platforms such as Security Onion, SIEM pipelines, or AI-driven reporting systems.

Safety

Use only on systems you own or have explicit authorization to test.
Northuldra is designed for controlled lab environments, training scenarios, and defensive research workflows.

Features

Interactive CLI workflow with guided execution

Preset orchestration of reconnaissance tooling

Structured JSONL logging for repeatable telemetry generation

Designed to integrate into SOC lab pipelines and detection engineering exercises

Requirements

Bash

Optional tools used by presets:

nmap

whatweb

nikto

gobuster

sslscan

enum4linux

snmpwalk
