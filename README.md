## neterpreter
Converts raw nessus output CSV to report (WIP) 

Feed the script a raw nessus output CSV with all additional data options ticked and sorted by CVSS V3 score. Using mail merge the script will create a base report based off the nessus input. Feel free to modify templates.

## Usage 
usage: neterpreter.py [-h] [-i FILEIN] [-c CUSTOMER] [-o FILEOUT] 
 
Script to convert Nessus CSV to report. 
 
required arguments: 
  -i FILEIN    Nessus csv export (sort by cvss v3 low-high). 
  -c CUSTOMER  Customer for templates. 
 
optional arguments: 
  -o FILEOUT   Output all template files. 
 
## Example 
./neterpreter.py -i nessus_input.csv -c Nobody -o report 
