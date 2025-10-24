# Building a firmware knowledge graph in Neo4j using Cyber language
1. Create indexes
Only execute once
Create 3 indexes in the database to improve the speed of data import. This data structure only contains 3 types of entities: Firmware, Binary, and CVE.
CREATE CONSTRAINT firmware_name IF NOT EXISTS FOR (f:Firmware) REQUIRE f.name IS UNIQUE;
CREATE CONSTRAINT binary_name IF NOT EXISTS FOR (b:Binary) REQUIRE (b.name,b.firmware) IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE (c.id,c.firmware) IS UNIQUE;

2. Import firmware
Modify the file path, you can import it multiple times, and when importing other files, modify the file name. Note that the file should be placed in the import folder in advance.
Write the firmware into the Neo4j database
LOAD CSV WITH HEADERS FROM 'file:///tXX_version.csv' AS row
WITH DISTINCT row.`Firmware Name` AS firmwareName
MERGE (f:Firmware {name: firmwareName});

3. Import binary
Modify the file path, you can import it multiple times, and when importing other files, modify the file name. Note that the file should be placed in the import folder in advance. Note to modify the firmware name
Import binaries into the Neo4j database
with 'tplink_archer_c5v2_us-up-ver3' as firmwarename
LOAD CSV WITH HEADERS FROM 'file:///tplink_archer_c5v2_Binary.csv' AS row
MERGE (b:Binary {name: row.`Binary Name`, id: toInteger(row.ID),firmware:firmwarename});

4. Set firmware\binary relationship
Modify the file path, you can import it multiple times, and when importing other files, modify the file name. Note that the file should be placed in the import folder in advance.
Create component and version attributes, put them in the binary.
LOAD CSV WITH HEADERS FROM 'file:///tplink_arcXX_version.csv' AS row 
with row.`Firmware Name` as  firmwarename,row.`Binary Name` as binaryname,collect(distinct row.`Component Name`) as compname,collect(distinct row.`Component Version`
) as compversion
MATCH (b:Binary {name: binaryname,firmware:firmwarename})

MATCH (f:Firmware {name: firmwarename})
MERGE (f)-[:CONTAINS]->(b)  //f包含b
with b,compname,compversion
set b.ComponentName=compname,b.ComponentVersion=compversion

5. Vulnerability   binary and vulnerability relationship
Modify the file path, you can import it multiple times, and when importing other files, modify the file name. Note that the file should be placed in the import folder in advance.
Write the vulnerability information into the database, and create the relationship AFFECTED_BY(binary affected by vulnerability) between the binary and the vulnerability. The relationship name feels too long.
LOAD CSV WITH HEADERS FROM 'file:///tplink_archer_c5v2_cve.csv' AS row
with row,row.`Firmware Name` as  firmwarename,row.`Binary Name` as binaryname
WHERE row.`CVE ID` IS NOT NULL
MERGE (cve:CVE {id: row.`CVE ID`,firmware:firmwarename})
SET 
  cve.description = row.Description,
  cve.cvss3_score = CASE WHEN row.`CVSS v3 Score` IS NOT NULL AND row.`CVSS v3 Score` <> '' THEN toFloat(row.`CVSS v3 Score`) ELSE null END,
  cve.cvss3_severity = CASE WHEN row.`CVSS v3 Severity` IS NOT NULL AND row.`CVSS v3 Severity` <> '' THEN row.`CVSS v3 Severity` ELSE null END,
  cve.cvss2_score = CASE WHEN row.`CVSS v2 Score` IS NOT NULL AND row.`CVSS v2 Score` <> '' THEN toFloat(row.`CVSS v2 Score`) ELSE null END,
  cve.cvss2_severity = CASE WHEN row.`CVSS v2 Severity` IS NOT NULL AND row.`CVSS v2 Severity` <> '' THEN row.`CVSS v2 Severity` ELSE null END
WITH row, cve,firmwarename,binaryname
MATCH (c:Binary{name: binaryname, firmware:firmwarename})
MERGE (c)-[:AFFECTED_BY]->(cve);

6. Binary relationship
Modify the file path, you can import it multiple times, and when importing other files, modify the file name. Note that the file should be placed in the import folder in advance.
Provide the relationship between the binary and the binary, create the relationship between the binary and the binary.
with 'tplink_archer_c5v2_us-up-ver3' as firmwarename
LOAD CSV WITH HEADERS FROM 'file:///tplink-archer_c5v2_edges.csv' AS row
MATCH (source:Binary {name: row.Source,firmware:firmwarename})
MATCH (target:Binary {name: row.Target,firmware:firmwarename})
MERGE (source)-[r:INTERACTS_WITH {
  relation: row.Relation, 
  label: CASE WHEN row.Label IS NULL THEN "" ELSE row.Label END, 
  color: CASE WHEN row.Color IS NULL THEN "" ELSE row.Color END
}]->(target);

7. View binary:
MATCH (a:Binary)
RETURN a

8. Calculate the number of CVE for each binary
Allow repeated execution
The relationship between the binary and the vulnerability is    binary->AFFECTED_BY->vulnerability.
The binary is associated with the vulnerability, calculate the data of the vulnerability associated with each binary, that is, calculate the CVE number, formula: Ncve
Write the calculation result into each binary. So the binary has an additional variable Ncve. In order to make each binary have Ncve, it is changed to
MATCH (m:Binary)
OPTIONAL MATCH (m)-[r2:AFFECTED_BY]->(x:CVE)
WITH m, COUNT(DISTINCT x) AS cnt
SET m.Ncve = COALESCE(cnt, 0)
9. Calculate the cvss score for each binary
Allow repeated execution
If cvss3_score exists, take the value of cvss3_score, otherwise take the value of cvss2_score
According to the rule, each vulnerability has the scores of cvss2 and cvss3. If the score of cvss3 exists, use cvss3, otherwise use cvss2. Recalculate the score of each vulnerability, generate score and set it to the vulnerability entity.
MATCH (x:CVE)
SET x.score = CASE 
  WHEN x.cvss3_score IS NOT NULL THEN x.cvss3_score
  WHEN x.cvss2_score IS NOT NULL THEN x.cvss2_score
  ELSE 0
END

10. Calculate the maximum cvss score for each firmware
Allow repeated execution
When calculating the vulnerability factor, you need to calculate the maximum vulnerability score for each firmware. That is, the maximum value of cvss3 and cvss2.
Since there may be multiple firmwares in the database, you need to group by firmware to calculate the maximum vulnerability score for each firmware,
Write this score to the firmware (score) and the firmware associated binary (max_cve_score).
match (f:Firmware)-[r]->(b:Binary)-[r2]->(cve:CVE)
with f,max(COALESCE(cve.cvss3_score,cve.cvss2_score)) as score
match (f)-[r]->(b:Binary)
set f.score=score,b.max_cve_score=score


11. Calculate the shortest length of each node to each entry point
According to the entry point program to calculate the shortest number of jumps for all binaries to reach the entry program, each relationship counts 1 jump.
According to the provided httpd, it is found that there is no entry relationship. So temporarily use httpd as the entry program for demonstration.
// 3. Handle isolated nodes (nodes with only outgoing edges) and set their minstep to 0 [directly count other binaries without minstep, directly set minstep=0 for those without minstep]

MATCH (binary:Binary)
WHERE binary.minstep IS NULL
SET binary.minstep = 0


12. Set the number of possible routes from each node to the entry point
Allow repeated execution
A program can reach the entry point in several ways.
After data import, it is found that there are circular routes between programs, which will cause a loop when searching for routes, and cannot find routes accurately.

// 1. 将 ‘ping6’, ‘httpd’, ‘nvram’ 的 linecnt设为 1
UNWIND ['ping6', 'httpd', 'nvram'] AS name
MATCH (start:Binary {name: name})
SET start.linecnt = 1


//2. 
UNWIND ['wscd', 'httpd', 'miniupnpd','query_3g_status','dnrd'] AS name  //'miniupnpd', 'pppd', 'dhttpd'
MATCH (start:Binary), (end:Binary {name: name})
WHERE start <> end
CALL apoc.path.expandConfig(start, {
    relationshipFilter: "<",  
    terminatorNodes: [end],   
    maxLevel: 10,             
    uniqueness: "NODE_GLOBAL" 
}) YIELD path
with start,path,count(path) AS cnt
set start.linecnt=case when start.linecnt is null then cnt
else start.linecnt+cnt
end

// 3. Handle isolated nodes (nodes with only outgoing edges) and set their minstep to 0 [directly count other binaries without linecnt, directly set linecnt=0 for those without linecnt]
MATCH (binary:Binary)
WHERE binary.linecnt IS NULL
SET binary.linecnt= 0

13. Calculate wcve
Allow repeated execution
//1. Calculate Wcve  According to the previous calculation results, Wcve can be calculated, and the Wcve value of each binary is calculated according to the relationship between the binary and the vulnerability, and the Wcve is recorded on the corresponding binary. The first one is not used, the method below is used)
match (a:Binary)-[r1]->(c:CVE)
with distinct a, c
with a,round( sum(c.score)/(10*a.max_cve_score)+1,2) as wcve
set a.Wcve=wcve

//2. New formula requirement (change 10 to the number of vulnerabilities): After viewing, it is found that it is very good, and the result can be controlled in [0-1] when the number of vulnerabilities is large, only tends to 1.
//The result can be calculated
match (a:Binary)-[r1]->(c:CVE)
with distinct a, c
with a,round( sum(c.score)/(count(c.score)*a.max_cve_score),2) as wcve
set a.Wcve=wcve


//3. For binaries without Wcve values
MATCH (binary:Binary)
WHERE binary.Wcve IS NULL
SET binary.Wcve= 0

14. Calculate Wpath
Allow repeated execution
According to Wpath, it can also be calculated. According to the formula, it can be calculated directly. Write the result into the program (Binary) entity, and record the result in the wpath attribute. Note: PI value can be ignored, because there is no associated Wpath, directly set wpath to 0.
MATCH (a:Binary)
WITH a, 
     CASE 
       WHEN a.minstep IS NULL THEN 0
       WHEN a.minstep = 0 THEN log(1 + a.linecnt) / 1  // Avoid division by zero
       ELSE log(1 + a.linecnt) / a.minstep
     END AS wpath
SET a.Wpath = wpath

15. Calculate W(pi)
Allow repeated execution
Calculate the value of W, W=Wcve+ WPath   set this value to the program (Binary).
And set the w value on all relationships between the binary and the binary, for subsequent calculation usage.
match (a:Binary)
with a, case when a.minstep is null then 0 else  a.Wpath+a.Wcve end as w
set a.w=w;

match (m)-[r:INTERACTS_WITH]->(n)
set r.w=0;

match (a:Binary)-[r]->(b:Binary)
set r.w=a.w

16. Projection
Allow repeated execution
Create projection, the projection name is: graph_binary, the entity used is: Binary, the relationship is: INTERACTS_WITH
The projection can only be created once
call gds.graph.drop("graph_binary")
CALL gds.graph.project(
  'graph_binary',  
  'Binary',                  
  {
    INTERACTS_WITH: {        
      orientation: 'NATURAL', 
      properties: {  
        w: { property: 'w' }
      }
    }
  }
) 


17. Calculate PageRank
CALL gds.pageRank.write(
  'graph_binary',
  {
    maxIterations: 20,
    dampingFactor: 0.85,
    relationshipTypes: ['INTERACTS_WITH'],
    nodeLabels: ['Binary'],
    writeProperty: 'pagerank'
  }
)

Recalculate new pagerank_yh (this method is very good)

MATCH (b:Binary)
SET b.pagerank_yh = b.pagerank + coalesce(b.w, 0)

18. Query results
Use cypher to query pagerank and sort the calculation results
match (m:Binary)
where m.pagerank is not null
return m.name,m.pagerank,m.firmware,m.pagerank_yh
order by m.pagerank desc
limit 100