#!/usr/bin/python3

import pdfkit
import os
import json
import hashlib
import urllib.request
import shutil

#1. generate copy of json file - DONE
#1. create list of all "Vendor Advisory" URLs from json file - DONE
#2. get PDF scrape of all URLs in list - DONE
#3. create new file name for each pdf based on hash of pdf file - DONE
#5. replace original URL in json file with new URL - DONE
#6. replace original json file

JSON_DIR = './json/'
PDF_DIR = './pdf/'
SOURCE_JSON = 'cve.json'
MOD_JSON = 'cve_mod.json'
PDF_BASE_PATH = 'http://opencve.local/pdfs/'
TAG_SELECTOR = ['Vendor Advisory', 'Third Party Advisory']
URL_LIST = []

def test_url(url):
	print(F'Testing URL: {url}')
	response = urllib.request.urlopen(url)
	status_code = response.getcode()
	#print(status_code)
	return(status_code)

def get_pdf(url):
	print(F'Attempting to convert URL {url} to pdf...')
	pdf = pdfkit.from_url(url, False)
	#pdf = b'blahblahblah'
	return(pdf)
	

#test directories exist
if os.path.isdir(JSON_DIR) != True:
	os.mkdir(JSON_DIR)
if os.path.isdir(PDF_DIR) != True:
	os.mkdir(PDF_DIR)
#extract URLs based on tags
if os.path.isfile(JSON_DIR+SOURCE_JSON):
	shutil.copy2(JSON_DIR+SOURCE_JSON, JSON_DIR+MOD_JSON)
	with open(JSON_DIR+MOD_JSON, 'r') as json_file:
		data = json.load(json_file)
		for cve in data["CVE_Items"]:
			#print(F'ID: {cve["cve"]["CVE_data_meta"]["ID"]}')
			for ref in cve["cve"]["references"]["reference_data"]:
				for tag in TAG_SELECTOR:
					if tag in ref["tags"]: 
						#print(F'ID: {cve["cve"]["CVE_data_meta"]["ID"]}')
						#print(F'URL: {ref["url"]}')
						url_dict={}
						url_dict["cve"]=cve["cve"]["CVE_data_meta"]["ID"]
						url_dict["original_url"]=ref["url"]
						URL_LIST.append(url_dict)
else:
	print(F'ERROR: file not found - {JSON_DIR+SOURCE_JSON}')
	print('Cannot continue.')
	exit()

#debug output	
print(F'URLs: {URL_LIST}')
#print(F'CVE count: {len(URL_LIST)}')
#exit()

#scrape URLs for content, create PDFs
if len(URL_LIST) > 0:
	for url in URL_LIST:
		try:
			_url=url["original_url"]
			response = test_url(_url)
			#response = 200
			if response == 200:
				pdf = get_pdf(_url)
				if len(pdf) > 0:
					pdf_md5 = hashlib.md5(pdf).hexdigest()
					print(F'MD5 hash of pdf: {pdf_md5}')
					file_name=pdf_md5+".pdf"
					with open(PDF_DIR+file_name, 'wb') as f:
						f.write(pdf)
						f.close()
					if os.path.isfile(PDF_DIR+file_name):
						url["pdf"]=file_name
				else:
					print(F'ERROR: zero sized pdf object: {pdf}')
			else:
				print(F'URL response bad: {_url}')
		except Exception as error:
			print(F'ERROR: {error}')

#debug display results:
print(F'URL_LIST before url replacement: {URL_LIST}')
#print(F'PDF count: {len(PDF_LIST)}')

for cve in data["CVE_Items"]:
	for mod in URL_LIST:
		if cve["cve"]["CVE_data_meta"]["ID"] == mod["cve"]:
			for ref in cve["cve"]["references"]["reference_data"]:
				if ref["url"] == mod["original_url"]:
					ref["url"] = PDF_BASE_PATH+mod["pdf"]
					ref["name"] = PDF_BASE_PATH+mod["pdf"]

#print(F'JSON after url replacement: {data["CVE_Items"]}')
with open(JSON_DIR+MOD_JSON, 'w') as f:
						json.dump(data, f, indent=2)
						f.close()

#validate json before replacing original
with open(JSON_DIR+MOD_JSON, 'r') as json_file:
	if json.load(json_file):
		print(F'OK: valid json file detected: {JSON_DIR+MOD_JSON}')



