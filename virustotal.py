#!/usr/bin/python3

from tabulate import tabulate
import json
import time
import os
import requests
import getpass

Apikey = getpass.getpass("Enter Api-key: ")
Files = input("Enter filename or file path: ")

headers={
		'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0',
		'x-apikey' : '{}'.format(Apikey)
}

files = {
			'file' : open('{}'.format(Files),'rb')
}

api_file = "https://www.virustotal.com/api/v3/files"

def analysis():
	try:
		response = requests.post(api_file, headers = headers, files = files)
		res = response.json()
		id = res['data']['id']
		api_id="https://www.virustotal.com/api/v3/analyses/{}".format(id)
	except:
		print("[X] Incorrect Api-key")
		exit()

	while True:

		time.sleep(30)
		response_ana = requests.get(api_id, headers = headers)
		res_ana = response_ana.json()
		if res_ana['data']['attributes']['status'] == "completed":
			os.system("clear")
			break
		else:
			print("Loading ...")

	results = res_ana['data']['attributes']['results']
	data = []
	for result in results:
		if results[result]['category'] == "malicious":
			data.append([results[result]['engine_name'],"XXXX\t" + results[result]['category']])
		else:
			data.append([results[result]['engine_name'],"V\t" + results[result]['category']])
	print(tabulate(data, headers = ["Engine name","Detection result"]))

if __name__ == "__main__":

	analysis()

