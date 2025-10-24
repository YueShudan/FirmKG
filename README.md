# FirmKG
Security Risk Assessment of IoT Firmware Binaries

# Overview
FirmKG first employs static analysis to extract key firmware information, such as binary dependencies and known vulnerabilities. It then builds a vulnerability knowledge graph using Cypher, representing entities, relationships, and attributes. Finally, an optimized PageRank algorithm calculates a security risk score for each binary based on its dependencies and vulnerability severity.


We present our approach and the findings of this work in the following research paper:

FirmKG: Security risk assessment of IoT firmware binaries based on knowledge graph

# Repository Structure
There are four main directories:

