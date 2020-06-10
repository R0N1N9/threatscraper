import requests, os
from art import *

Art=text2art("ThreatScraper")

url = 'https://www.virustotal.com/vtapi/v2/file/report'

#print('Please specify a hash: ')
#hash = input()

hashlist = open('hashes.txt', 'r')
threatlist = open('threatlist.txt', 'w')

print('What\'s the threat?')
threat = input()

for hash in hashlist:
    params = {'apikey': '76be9f910ae56ef01909aaa7e5e6527ec77186e2e85d896017fadc364ae92e98', 'resource': hash}
    response = requests.get(url, params=params)

    #print(response.json()['scans'])

    for item in response.json()['scans']:
        result = response.json()['scans'][item]['result']
        if str(threat).lower() == str(result).lower():
        #print(type(result))
            threatlist.write(hash)


hashlist.close()
threatlist.close()
