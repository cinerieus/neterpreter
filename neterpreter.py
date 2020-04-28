#!/usr/bin/env python3
#
# Requirements: docx-mailmerge
# Author: Cinerieus
# Version 1.0.0
#
######################

import sys
import argparse
import os
import traceback
import csv
from mailmerge import MailMerge as template

class neterpreter():

    def createTemp(self,fileout,customer):
        try:
            exec_rowlist = []
            overview_rowlistc = []
            overview_rowlisth = []
            overview_rowlistm = []
            overview_rowlistl = []
            detail_rowlistc = []
            detail_rowlisth = []
            detail_rowlistm = []
            detail_rowlistl = []
            
            for item in self.data_sorted:
                ID = item[1]['ID']
                rowdict = {'risk':item[1]['risk'],
                           'desc':item[0],
                           'count':str(len(item[1]['assets']))}

                detail_dict = {'risk':item[1]['risk'],
                               'name':item[0],
                               'cve':'\n'.join(item[1]['CVE']),
                               'desc':item[1]['background'],
                               'remediation':item[1]['remediation'],
                               'ip':list(item[1]['assets'].values())}

                if 'H' in ID or 'C' in ID:
                    exec_rowdict = rowdict
                    exec_rowdict.update({'uid':ID})
                    exec_rowlist.append(exec_rowdict)
                    if 'C' in ID:
                        overview_rowdictc = rowdict 
                        overview_rowdictc.update({'cuid':ID,'cve':'\n'.join(item[1]['CVE'])})
                        overview_rowlistc.append(overview_rowdictc)
                        detail_dict.update({'cuid':ID})
                        detail_rowlistc.append(detail_dict)
                    if 'H' in ID:
                        overview_rowdicth = rowdict
                        overview_rowdicth.update({'huid':ID,'cve':'\n'.join(item[1]['CVE'])})
                        overview_rowlisth.append(overview_rowdicth)
                        detail_dicth = detail_dict
                        detail_dicth.update({'huid':ID})
                        detail_rowlisth.append(detail_dicth)
                if 'M' in ID:
                    overview_rowdictm = rowdict
                    overview_rowdictm.update({'muid':ID,'cve':'\n'.join(item[1]['CVE'])})
                    overview_rowlistm.append(overview_rowdictm)
                    detail_dict.update({'muid':ID})
                    detail_rowlistm.append(detail_dict)
                if 'L' in ID:
                    overview_rowdictl = rowdict
                    overview_rowdictl.update({'luid':ID,'cve':'\n'.join(item[1]['CVE'])})
                    overview_rowlistl.append(overview_rowdictl)
                    detail_dict.update({'luid':ID})
                    detail_rowlistl.append(detail_dict)
           
            doc = template('./templates/exec_temp.docx')
            doc.merge(customer=customer)
            doc.merge_rows('uid', exec_rowlist)
            doc.write('./'+fileout+'/'+fileout+'_exec.docx')

            for k,v in self.stats.items():
                self.stats[k] = str(v)
            statlist = [self.stats]
            doc = template('./templates/overview_temp.docx')
            doc.merge_rows('cuid', overview_rowlistc)
            doc.merge_rows('huid', overview_rowlisth)
            doc.merge_rows('muid', overview_rowlistm)
            doc.merge_rows('luid', overview_rowlistl)
            doc.merge_rows('Critical', statlist)
            doc.write('./'+fileout+'/'+fileout+'_overview.docx')

            doc = template('./templates/detailCritical_temp.docx')
            doc.merge_templates(detail_rowlistc, separator='page_break')
            doc.write('./'+fileout+'/'+fileout+'_detailCritical.docx')

            doc = template('./templates/detailHigh_temp.docx')
            doc.merge_templates(detail_rowlisth, separator='page_break')
            doc.write('./'+fileout+'/'+fileout+'_detailHigh.docx')

            doc = template('./templates/detailMedium_temp.docx')
            doc.merge_templates(detail_rowlistm, separator='page_break')
            doc.write('./'+fileout+'/'+fileout+'_detailMedium.docx')

            doc = template('./templates/detailLow_temp.docx')
            doc.merge_templates(detail_rowlistl, separator='page_break')
            doc.write('./'+fileout+'/'+fileout+'_detailLow.docx')

        except Exception as e:
            print('Error in createExec:')
            print(e)
            traceback.print_tb(e.__traceback__)
            sys.exit(2)

    def formatting(self,nessus_dict):
        try:
            for row in nessus_dict:
                try:
                    cvss = float(row['CVSS v3.0 Base Score'])
                    risk = 'None'
                    if cvss > 0 and cvss < 4:
                        risk = 'Low'
                    elif cvss >= 4 and cvss < 7:
                        risk = 'Medium'
                    elif cvss >= 7 and cvss < 9:
                        risk = 'High'
                    elif cvss >= 9 and cvss <= 10:
                        risk = 'Critical'

                except:
                    try:
                        cvss = float(row['CVSS'])
                        risk = row['Risk']
                    except:
                        cvss = float(0)
                        risk = row['Risk']
                
                vuln = row['Name']
                host = row['Host']
                port = row['Port']
                desc = row['Description']
                cve = row['CVE']
                remediation = row['Solution']

                #self.stats[risk] += 1
                #ID = list(risk)[0]+str(self.stats[risk])

                if vuln not in self.data:
                    self.data[vuln] = {'ID':'', 'background':desc, 'risk':risk, 'base_score':cvss, 'remediation':remediation, 'CVE':[], 'assets':{}, 'context':'', 'description':''}
                    self.data[vuln]['CVE'].append(cve)
                    self.data[vuln]['assets'][host] = {'ip':host, 'ports':[port]}
                else:
                    if cve not in self.data[vuln]['CVE']:
                        self.data[vuln]['CVE'].append(cve)
                    if host not in self.data[vuln]['assets']:
                        self.data[vuln]['assets'][host] = {'ip':host, 'ports':[port]}
                    elif port not in self.data[vuln]['assets'][host]['ports']:
                        self.data[vuln]['assets'][host]['ports'].append(port)

            self.data_sorted = sorted(self.data.items(), key = lambda x: x[1]['base_score'], reverse=True) 

            for item in self.data_sorted:
                self.stats[item[1]['risk']] += 1
                item[1]['ID'] = list(item[1]['risk'])[0]+str(self.stats[item[1]['risk']])
                if item[1]['CVE'][0] == '':
                    item[1]['CVE'] = ['N/A']
                for v in item[1]['assets'].values():
                    v['ports'] = '\n'.join(v['ports'])

        except Exception as e:
            print('Error in formatting:')
            print(e)
            traceback.print_tb(e.__traceback__)
            sys.exit(2)



    def __init__(self,filein,fileout,customer):
        self.stats = {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'None':0}
        self.execdata = {}
        self.data = {}

        with open(filein, 'r') as csvin:
            nessus_dict = csv.DictReader(csvin)
            self.formatting(nessus_dict)
        for k in self.data.keys():
            print(k)
        
        if fileout:
            os.mkdir(fileout)
            self.createTemp(fileout,customer)

        print('Stats:')
        print(self.stats)
        #print('\n')
        #for x in self.data_sorted:
        #    print(x)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script to convert Nessus CSV to report.')
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument('-i', action="store", dest="filein", help='Nessus csv export (sort by cvss v3 low-high).')
    required.add_argument('-c', action="store", dest="customer", help='Customer for templates.')
    optional.add_argument('-o', action="store", dest="fileout", help='Output all template files.')
    args = parser.parse_args()

    if not args.filein or not args.customer:
        parser.print_help(sys.stderr)
        sys.exit(1)

    neterpreter(args.filein,args.fileout,args.customer)
