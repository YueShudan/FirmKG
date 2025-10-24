# FirmKG
Security Risk Assessment of IoT Firmware Binaries

# Overview
FirmKG first employs static analysis to extract key firmware information, such as binary dependencies and known vulnerabilities. It then builds a vulnerability knowledge graph using Cypher, representing entities, relationships, and attributes. Finally, an optimized PageRank algorithm calculates a security risk score for each binary based on its dependencies and vulnerability severity.


We present our approach and the findings of this work in the following research paper:

FirmKG: Security risk assessment of IoT firmware binaries based on knowledge graph

# Repository Structure
There are four main directories:
buildKG.py : Building a firmware knowledge graph in Neo4j using Cyber language

comVersion.py : Given the firmware, analyze the number of binaries, then analyze the versions of the binaries, and provide json and csv

finderCVE.py : The implementation has enabled the identification of vulnerabilities corresponding to versions in CSV files

process_edges.py : Output the generated relationship

scanBinaries.py : Scan the binary files in the firmware and generate a CSV file

