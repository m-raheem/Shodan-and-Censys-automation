import json
import requests
import shodan
import configparser
import os

CONFIG_FILE_NAME = 'Configuration.conf'
CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_FILE_NAME)

def shodan_IPenum(ip):
        SHODAN_API_KEY = str(CONFIG['SHODAN']['API_KEY'])
        api = shodan.Shodan(SHODAN_API_KEY)
        print(api)
        # Lookup the host
        response = api.host(ip)
        data = {
                'ip': response.get('ip_str','n/a'),
                'hostname': response.get('hostnames','n/a'),
                'organization': response.get('org'),
                'ports': response.get('ports','n/a'),
                'vuln' : response.get('vulns' ,'n/a'),
                'isp'   : response.get('isp' ,'n/a'),
                'hostnames' : response.get('hostnames','n/a'),
                'domains'  : response.get('domains','n/a')
        }

        response_data_list = response.get('data', {})
        data['services'] = []
        
        for item in response_data_list:
                temp_dict = {}
                data_port = 'data_port_'+str(item.get('port'))
                temp_dict[data_port] = {}
                if 'location' not in data and 'location' in item:
                        data['location'] = item.get('location')
                temp_dict[data_port]['os'] = item.get('os','n/a')
                temp_dict[data_port]['banner'] = item.get('data','n/a')
                temp_dict[data_port]['port'] = item.get('port')

                if 'http' in item:
                        http_data = item['http']
                        temp_dict[data_port]['favicon'] = http_data.get('favicon','n/a')
                        temp_dict[data_port]['waf_header'] = http_data.get('waf','n/a')
                        temp_dict[data_port]['server'] = http_data.get('server','n/a')
                        temp_dict[data_port]['sitemap'] = http_data.get('sitemap','n/a')
                        temp_dict[data_port]['html_title'] = http_data.get('title','n/a')
                        temp_dict[data_port]['redirects'] = http_data.get('redirects','n/a')
                data['services'].append(temp_dict)

                #print(http_data)
                
                
                # Extract the CPE information for each open port
                if 'cpe' in item:
                        cpe = item['cpe']
                        data['cpe'] = cpe
                # Extract the protocol handshake for each open port
                elif 'ftp' in item:
                        data['ftp'] = item['ftp']
                elif 'ssh' in item:
                        data['ssh'] = item['ssh']
                elif 'ftpd' in item:
                        data['ftpd'] = item['ftpd']
        

        # with open('output_Shodan-juicy.json', 'w') as f:
        #         json.dump(data, f, indent=4)
        return data



###########################################Censys-IPENUM#######################################

def censys_IPenum(query):

    # API endpoint
    url = f"https://search.censys.io/api/v2/hosts/{query}"
    CENSYS_AUTH_TOKEN = CONFIG['CENSYS']['AUTH_TOKEN']

    # Headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {CENSYS_AUTH_TOKEN}"
    }
    print(headers)

    # Send the request
    resp = requests.get(url, headers=headers)
    print(resp)
    if resp.status_code != 200:
          print("No response from Censys")
    # Parse the JSON response
    total_resp = resp.json()
    response = total_resp.get('result')
    data = {
        'ip': response.get('ip','n/a'),
    }
    response_data_list = response.get('services', {})
    data['services'] = []
    for item in response_data_list:
                temp_dict = {}
                data_port = 'data_port_'+str(item.get('port'))
                temp_dict[data_port] = {}
                temp_dict[data_port]['port'] = item.get('port','n/a')
                temp_dict[data_port]['banner'] = item.get('banner','n/a')
                temp_dict[data_port]['software'] = item.get('software','n/a')
                temp_dict[data_port]['service_name'] = item.get('service_name','n/a')
                if 'http' in item:
                       temp_dict[data_port]['server'] = item['http'].get('response','n/a').get('headers','n/a').get('Server','n/a')
                       temp_dict[data_port]['html_title'] = item['http'].get('response','n/a').get('html_title')
                       temp_dict[data_port]['uri'] = item['http'].get('response','n/a').get('uri')
                data['services'].append(temp_dict)
    data['dns'] =  response.get('dns','n/a'),
    data['asn'] = response.get('autonomous_system','n/a'),
    data['location'] =  response.get('location','n/a')
    return data



def merge_dict(dict1, dict2):
    """Recursive function to merge two dictionaries"""
    for key in dict2:
        if key in dict1:
            if isinstance(dict1[key], int) or isinstance(dict2[key], int):
                continue
            elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                # If both values are dictionaries, merge them recursively
                merge_dict(dict1[key], dict2[key])
            elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                # If both values are lists, merge them by calling the merge_dict function on each dictionary in the list
                dict1[key] = [merge_dict(dict1_elem, dict2_elem) for dict1_elem, dict2_elem in zip(dict1[key], dict2[key])]
            elif isinstance(dict1[key], list) and isinstance(dict2[key], dict):
                # If the value in dict2 is a dictionary and the value in dict1 is a list, append the dictionary to the list
                dict1[key].append(dict2[key])
            elif len(dict2[key]) > len(dict1[key]):
                # If both values are not dictionaries or lists, and the value in dict2 is longer, replace the value in dict1 with the value from dict2
                dict1[key] = dict2[key]
        else:
            # If the key doesn't exist in dict1, add it and its value from dict2
            dict1[key] = dict2[key]
    return dict1

ip = os.argv[1]
censys_data = censys_IPenum(ip)
shodan_data = shodan_IPenum(ip)
# Merge the two dictionaries using the merge_dict() function

merged_data = merge_dict(censys_data, shodan_data)
# Write the merged and deduplicated dictionary to a new JSON file
with open('results.json', 'w') as f:
    json.dump(merged_data, f,indent=4)

