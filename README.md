# security-labs

Worked solutions to a set of hands-on offensive-security labs, each written up with the exact setup, commands and evidence.

## What it does

Nine lab reports, based on the [SEED Labs](https://seedsecuritylabs.org/), each reproducing a real attack or defence from scratch and explaining why it works:

| Lab | Topic |
|-----|-------|
| 1 | Linux security warm-up |
| 4 | Environment variables and Set-UID programs |
| 5 | Buffer overflow (stack smashing, shellcode) |
| 6 | Format-string attack |
| 7 | Cross-site scripting (stored XSS) |
| 9 | Symmetric-key encryption (block-cipher modes, frequency analysis) |
| 10 | Hash length-extension attack |
| 11 | Public-key infrastructure (PKI, certificates) |
| 13 | Packet sniffing and spoofing |

Each report walks through disabling protections where required (ASLR, stack canaries), building the vulnerable target, carrying out the attack, and capturing the result.

## Stack

C, Python, shell, OpenSSL, Scapy, Docker, and the SEED Labs Ubuntu VM. Reports in Markdown with screenshots under `Loogbooks/images/`.

## How to read and reproduce

Start from any file in `Loogbooks/`. Each report is self-contained: it lists the environment, the exact commands, and the expected output, so a lab can be reproduced on the SEED Labs VM by following it top to bottom.

## What I built

Group work for the Information Security course (2025/26). I researched, carried out and wrote up every lab except Logbook 4 (environment variables and Set-UID), which a teammate led. The write-ups are the deliverable; they are mine except where noted.

## What I would do differently

Write the reports in English rather than Portuguese so they travel further, and add a short "why this matters" section to each one tying the lab to a real-world CVE or incident. This is the work that pointed me toward security as a direction.
