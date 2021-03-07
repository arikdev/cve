from datetime import datetime
import requests
import json
import csv_tools as csv

CSV_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
CPE_TABLE = 'vul_cpe.csv'
PRODUCT_CPE_TABLE = 'vul_product_cpe.csv'

cves = []
cpe_db = {}

def get_cves(cpe_part, cpe_vendor, cpe_product, cpe_version, fcves):
    start_index = 0
    result_per_page = 16
    total_items_read = 0

    while True:
        request_content = 'https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=%d&resultsPerPage=%s&cpeMatchString=cpe:2.3:%s:%s:%s:%s' % (start_index, result_per_page, cpe_part, cpe_vendor, cpe_product, cpe_version)
        print(request_content)
        print('...')
        r = requests.get(request_content)
        try:
            j = json.loads(r.text)
        except:
            print('*** ERROR:' + r.text)
            continue
        total_results = j['totalResults']
        print('   --- Total results:' + str(total_results))
        result = j['result']
        items = result['CVE_Items']
        items_read = len(items)
        total_items_read += items_read
        f.write('Request:' + request_content)
        f.write(f'    ----- get cves %s:%s:%s:%s items read:%d totaol items read: %d \n' % (cpe_part, cpe_vendor, cpe_product, cpe_version, items_read, total_items_read))
        f.flush()
        for item in items:
            cve = item['cve']
            meta_data = cve['CVE_data_meta']
            id = meta_data['ID']
            if id in cves:
                continue
            cves.append(id)
            fcves.write(json.dumps(item) + '\n')
        if total_items_read >= total_results:
            break;
        start_index += items_read


class Cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global cpe_db
        cpe_id = tokens[0]
        if cpe_id not in cpe_db:
           cpe_db[cpe_id] = []
        cpe_entry = cpe_db[cpe_id]
        cpe_info = {}
        cpe_info['part'] = tokens[1]
        cpe_info['vendor']= tokens[2]
        cpe_info['product'] = tokens[3]
        cpe_entry.append(cpe_info)

class Product_cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        product_id = tokens[0]
        cpe_id = tokens[1]
        version = tokens[2]
        f.write("--- Processing: " + product_id + ' ' + cpe_id + ' ' + version + '\n')
        fcves = open("cves.json", "w")
        for var in cpe_db[cpe_id]:
            f.write('---  CPE variat:' + var['part'] + ' ' + var['vendor'] + ' ' + var['product'] + ' ' + version + '\n')
            get_cves(var['part'], var['vendor'], var['product'], version, fcves)
        fcves.close()

f = open("cve_log.txt", "w")
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
f.write('------------------Started---------------:' + current_time + '\n')

cpe_file = Cpe_file(CSV_HOME + CPE_TABLE)
cpe_file.process()

product_cpe_file = Product_cpe_file(CSV_HOME + PRODUCT_CPE_TABLE)
product_cpe_file.process()

now = datetime.now()
current_time = now.strftime("%H:%M:%S")
f.write('------------------Finished---------------:' + current_time + '\n')
f.write(str(len(cves)) + '\n')

