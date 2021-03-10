from time import sleep
import requests
import json
import sys
import re

TEST_CVE = 'CVE-2019-18786'

res = {}
files_found = 0

def handle_files(cve_id, files):
    global f
    global files_found
    for file in files:
        if cve_id not in res:
            info = {}
            info['files'] = []
            info['commits'] = []
            res[cve_id] = info
        if file not in res[cve_id]['files']:
            f.write('>>>>>FILE ' + cve_id + ' ' + file + '\n')
            res[cve_id]['files'].append(file)
            files_found += 1

def handle_commit(cve_id, url):
    if 'commit' not in url:
        return
    tokens = url.split('/')
    commit_id = tokens[-1]
    tokens = commit_id.split('=')
    commit_id = tokens[-1]
    if cve_id not in res:
       info = {}
       info['files'] = []
       info['commits'] = []
       res[cve_id] = info
    if commit_id not in res[cve_id]['commits']:
        res[cve_id]['commits'].append(commit_id)
        f.write('>>>>>COMMIT ' + commit_id + ' from url: ' + url + '\n')

def find_all(str, sub):
    start = 0
    while True:
        start = str.find(sub, start)
        if start == -1:
            return
        yield start
        start += len(sub)

def get_patch_files(cve_id, str_patch):
    files = []
    for diff_i in find_all(str_patch, '--- a/'):
        str = str_patch[diff_i:]
        if str.startswith('--- a/<a'):
            start_i = str.find('>') + 1
            end_i = str[start_i:].find('<')
            files.append(str[start_i:start_i + end_i])
        else:
            diff_tokens = str_patch[diff_i:].split(None, 2)
            comp_file = diff_tokens[1][1:]
            if '<' in comp_file:
                comp_file = comp_file.split('<')[0]
            files.append(comp_file)
    lines = str_patch.split('\n')
    for line in lines:
        if 'data-path=' in line:
            files.append(line.split('"')[1])
    return files

def handle_xen_patch(cve_id, patch_name):
    XEN_PREFIX = 'http://xenbits.xen.org/xsa/'
    xen_url = XEN_PREFIX + patch_name
    try:
        response = requests.get(xen_url)
    except:
        f.write('Eeception URL:' + url + '\n')
        return
    files = get_patch_files(cve_id, str(response.content, 'utf-8'))

    handle_files(cve_id, files)


def handle_xen(cve_id, str_patch):
    lines = str_patch.split('\n')
    for line in lines:
        if 'href' in line and 'patch' in line:
            ind = line.find('href=')
            if ind == -1:
                continue
            patch_name = line[ind:].split('"')[1]
            if 'patch' not in patch_name:
                continue
            handle_xen_patch(cve_id, patch_name)

def handle_bugzilla_readhat(cve_id, str_patch):
    lines = str_patch.split('\n')
    patch_id = -1
    for i,line in enumerate(lines):
        if 'Upstream patch:' in line:
            patch_id = i
            break
    if patch_id == -1:
        return
    for i in range(patch_id + 1, len(lines)):
        if 'https:' in lines[i]:
            patch_id = i
            break
    else:
        return

    url = lines[patch_id].split('"')[1]
    try:
        response = requests.get(url)
    except:
        f.write('Eeception URL:' + url + '\n')
        return
    handle_patch(cve_id, url, str(response.content, 'utf-8'))


def handle_patch(cve_id, url, str_patch):
    if url is None:
        return

    if 'xenbits' in url:
        handle_xen(cve_id, str_patch)
        return
    if 'bugzilla.redhat' in url: 
        handle_bugzilla_readhat(cve_id, str_patch)
        return

    handle_commit(cve_id, url)
    files = get_patch_files(cve_id, str_patch)
    if cve_id == TEST_CVE:
        print('PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP ' + TEST_CVE  + ' patch '  + url)
        print(files)
    handle_files(cve_id, files)

def is_relevant_url(url):
    relevant_strings = ['git', 'kernel.org', 'lkml.org', 'xenbits', 'bugzilla.redhat', 'linuxtv.org' ]

    for str in relevant_strings:
        if str in url:
            return True
    return False


def handle_ref(cve_id, r):
    #if 'tags' not in r:
        #return
    #tags = r['tags']
    #if 'Patch' not in tags:
    #   return
    if 'url' not in r:
       return
    url = r['url']
    if cve_id == TEST_CVE:
        print('DDDDDDDDDDDDDDDDDDDDD ' + TEST_CVE  + ' '  + url)
    if not is_relevant_url(url):
        return
    try:
      response = requests.get(url)
    except:
      f.write('Eeception URL:' + url + '\n')
      return
    handle_patch(cve_id, url, str(response.content, 'utf-8'))

def handle_description(cve_id, cve):
    if 'description' not in cve:
        return
    desc = cve['description']
    if 'description_data' not in desc:
        return;
    desc_data = desc['description_data']
    for i in desc_data:
        if 'value' not in i:
            continue
        handle_patch(cve_id, None, i['value'])


def handle_cve(item):
    cve = item['cve']
    cve_meta_data = cve['CVE_data_meta']
    #handle_description(cve_meta_data['ID'], cve)
    if 'references' not in cve:
        return
    references = cve['references']
    if 'reference_data' not in references:
        return
    ref_data = references['reference_data']
    #if cve_meta_data['ID'] != TEST_CVE:
    #    return
    for r in ref_data:
      handle_ref(cve_meta_data['ID'], r)

f = open("cve_reference_log.txt", "w")
fcves_refs = open("cves_refs.json", "w")
cves = []
with open('cves.json', 'r') as json_file:
    for line in json_file:
        data = json.loads(line)
        handle_cve(data)

for cve_id, cve_info in res.items():
    cve_ref = {}
    cve_ref['cve_id'] = cve_id
    cve_ref['files'] = cve_info['files']
    if 'commits' in cve_info:
        cve_ref['commits'] = cve_info['commits']
    fcves_refs.write(json.dumps(cve_ref) + '\n')

fcves_refs.close()

f.write('FINISH!!!!\n')
f.close()
