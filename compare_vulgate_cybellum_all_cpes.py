import json
import sys
import pandas as pd

# Vulgate  Get all the CVEs - 3 DBs Vulnerables,Filterd, UserIgnored -Data CVE, detail, list of CPEs
# Cybelum get all the CVEs - CVE, list of CPEs 

if len(sys.argv) < 3:
    print('usage: %s incident_report vulgate_report' % sys.argv[0])
    sys.exit()

cybelum_report = sys.argv[1]
vulgate_report = sys.argv[2]

vulgate = {}
vulgate['reported'] = {}
vulgate['ignored'] = {}
vulgate['falsePositive'] = {}

with open(vulgate_report, 'r') as vulgate_file:
    j = json.load(vulgate_file)

vuls = j['vulgateAuditReport']['vulnerableCpes']
for vul in vuls:
    upstream = vul['upstream']
    for i in vul['cves']:
         vulgate['reported'][i['cveId']] = upstream
    for i in vul['userIgnoredCves']:
         vulgate['ignored'][i['cveId']] = upstream
    for i in vul['autodetectedFalsePositiveCves']:
        vulgate['falsePositive'][i['cveId']] = {'upstream':upstream, 'justfication':i['justificationForFalsePositive']}

cybelum = {}
df = pd.read_excel(cybelum_report, 'Known Vulnerabilities')
cves_df = df.loc[(df['Status'] == 'undetermined')][['Name', 'Package']]
for i,r in cves_df.iterrows():
    cybelum[r['Name']] = r['Package']

report_fs_not_compiled = []
report_fs_compiled = []
report_fs_ui = []
report_ok = []
report_not_in_vulgate = []

for cve,package in cybelum.items():
    if cve in vulgate['reported']:
        report_ok.append(cve)
    elif cve in vulgate['falsePositive']:
        try:
            if 'not compiled' in vulgate['falsePositive'][cve]['justfication']:
                report_fs_not_compiled.append(cve)
            else:
                report_fs_compiled.append(cve)
        except:
            print('ERROR: ')
            print(vulgate['falsePositive'][cve])
    elif cve in vulgate['ignored']:
        report_fs_ui.append(cve)
    else:
        report_not_in_vulgate.append(cve)
              

print("REPORT")
print('--------------------------\n')

print('Cybelum report: ' + sys.argv[1])
print('vulgate report: ' + sys.argv[2])

print('\nFalse positive not compiled (' + str(len(report_fs_not_compiled)) + ') :')
print('---------------------------------------')
for cve in report_fs_not_compiled:
    print(cve, cybelum[cve], vulgate['falsePositive'][cve]['justfication'])

print('\nFalse positive not in Vulgate (' + str(len(report_not_in_vulgate)) + ') :')
print('---------------------------------------')
for cve in report_not_in_vulgate:
    print('NV' + ',' + cve + ',' +  cybelum[cve])
     
print('\nFalse positive compiled (' + str(len(report_fs_compiled)) + ') :')
print('---------------------------------------')
for cve in report_fs_compiled:
    print(cve, cybelum[cve], vulgate['falsePositive'][cve]['justfication'])

fn_count = 0
ok_count = 0
for cve in vulgate['reported']:
    if cve in cybelum:
       ok_count += 1
    else:
       fn_count += 1
print('\nFalse negative (' + str(fn_count) + ') :')
print('---------------------------------------')
for cve,upstream in vulgate['reported'].items():
    if not cve in cybelum:
        print(cve, upstream)

print('\nFalse positive USER ignored (' + str(len(report_fs_ui)) + ') :')
print('---------------------------------------')
for cve in report_fs_ui:
    print(cve, cybelum[cve])

#report_not_in_vulgate.append(cve)

print('\nOK (' + str(ok_count) + ') :')
print('---------------------------------------')
for cve,upstream in vulgate['reported'].items():
    if cve in cybelum:
        print(cve, upstream)


sys.exit()

df = pd.read_excel(cybelum_sbom, 'SBOM')[['Package Name', 'Version Name', 'CPEs']]
df.drop_duplicates(subset=['CPEs'], keep='first', inplace=True)
df.dropna(subset=['Version Name'], inplace=True)
packages_dict = {}
for i,r in df.iterrows():
   #print(r['Package Name'], r['CPEs'])
   packages_dict[r['Package Name'] + ':' + str(r['Version Name'])] = r['CPEs']

print('\n====================  SUMMARY ============================================================')
print('OK: ' + str(ok) + ' FALSENEGATIVE: ' + str(falseNegative) + ' FALSEPOSITIVE: ' + str(falsePositive) + ' USER IGNORED: ' + str(userIgnored))
