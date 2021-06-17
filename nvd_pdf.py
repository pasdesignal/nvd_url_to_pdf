#!/usr/bin/python3

import os
import json
import hashlib
import urllib.request
import shutil
from PyPDF2 import PdfFileReader, PdfFileWriter
import pdfkit

#1. generate copy of json file - DONE
#1. create list of all "Vendor Advisory" URLs from json file - DONE
#2. get PDF scrape of all URLs in list - DONE
#3. create new file name for each pdf based on hash of pdf file - DONE
#5. replace original URL in json file with new URL - DONE
#6. replace original json file - DONE

JSON_DIR = './json/'
PDF_DIR = './pdf/'
SOURCE_JSON = 'cve.json'
MOD_JSON = 'cve_mod.json'
PDF_BASE_PATH = 'http://opencve.local/pdfs/'
TAG_SELECTOR = ['Vendor Advisory', 'Third Party Advisory']
URL_LIST = [] #list of dicts of cves extracted from json according to tags
MOD_LIST = [] #list of dicts, only if the url was replaced by pdf

def test_url(url, alreadyDone):
	print(F'Testing URL: {url}')
	for done in alreadyDone:
		if url in done["sourceUrl"]:
			print(F'ACHTUNG: already go this one bro: {url}')
			status_code=666
			return(status_code, done["pdf"])
		else:
			pdf="none"
			response = urllib.request.urlopen(url)
			status_code = response.getcode()
			return(status_code, pdf)

def get_pdf(url):
	print(F'Attempting to convert URL {url} to pdf...')
	options = {'quiet': ''}
	pdf = pdfkit.from_url(url, False, options=options)
	return(pdf)

def meta_pdf_read(pdf):
	print(F'Reading metadata from PDF: {pdf}')
	_meta = open(pdf, 'rb')
	reader = PdfFileReader(_meta)
	metadata = reader.getDocumentInfo()
	_meta.close()
	return(metadata)

def meta_pdf_write(pdf, url):
	print(F'Attempting to add metadata to PDF: {pdf}')
	_meta = open(pdf, 'rb')
	reader = PdfFileReader(_meta)
	writer = PdfFileWriter()
	writer.appendPagesFromReader(reader)
	metadata = reader.getDocumentInfo()
	writer.addMetadata(metadata)
	writer.addMetadata({'/sourceUrl':url})
	fout = open(pdf, 'ab') #ab is append binary; if you do wb, the file will append blank pages
	writer.write(fout)
	fout.close()
	print(F'Completed metadata append.')

def get_processed(pdf_dir):
	SUB_PROCESSED = []
	for file in os.listdir(pdf_dir):
		if file.endswith(".pdf"):
			metadata = meta_pdf_read(pdf_dir+file)
			if "/sourceUrl" in metadata:
				print(F'sourceUrl found: {metadata["/sourceUrl"]}')
				_dict={"sourceUrl":metadata["/sourceUrl"], "pdf":pdf_dir+file}
				#SUB_PROCESSED.append(metadata["/sourceUrl"])
				SUB_PROCESSED.append(_dict)
	return(SUB_PROCESSED)

#main
#before all else, test directories exist etc
if os.path.isdir(JSON_DIR) != True:
	os.mkdir(JSON_DIR)
if os.path.isdir(PDF_DIR) != True:
	os.mkdir(PDF_DIR)
#check existing pdfs so we dont process them again...
alreadyDone = get_processed(PDF_DIR)
print(F'alreadyDone: {alreadyDone}')	
#extract URLs based on tags
if os.path.isfile(JSON_DIR+SOURCE_JSON):
	shutil.copy2(JSON_DIR+SOURCE_JSON, JSON_DIR+MOD_JSON)
	with open(JSON_DIR+MOD_JSON, 'r') as json_file:
		data = json.load(json_file)
		for cve in data["CVE_Items"]:
			for ref in cve["cve"]["references"]["reference_data"]:
				for tag in TAG_SELECTOR:
					if tag in ref["tags"]: 
						url_dict={}
						url_dict["cve"]=cve["cve"]["CVE_data_meta"]["ID"]
						url_dict["original_url"]=ref["url"]
						URL_LIST.append(url_dict)
else:
	print(F'ERROR: file not found - {JSON_DIR+SOURCE_JSON}')
	print('Cannot continue.')
	exit()
#scrape URLs for content, create PDFs
if len(URL_LIST) > 0:
	for url in URL_LIST:
			try:
				_url=url["original_url"]
				response, response_pdf = test_url(_url, alreadyDone)
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
							meta_pdf_write(PDF_DIR+file_name, _url)
							MOD_LIST.append(url)
					else:
						print(F'ERROR: zero sized pdf object: {pdf}')
				else:
					if response == 666:
						url["pdf"]=response_pdf
						MOD_LIST.append(url)
					else:
						print(F'URL response bad: {_url}')
			except Exception as error:
				print(F'ERROR: {error}')
#replace original urls with pdf file instead of webpage
if len(MOD_LIST) > 0: 
	print(F'URL_LIST before url replacement: {URL_LIST}')
	for cve in data["CVE_Items"]:
		for mod in MOD_LIST:
			print(F'!!!###MOD:{mod}')
			if cve["cve"]["CVE_data_meta"]["ID"] == mod["cve"]:
				for ref in cve["cve"]["references"]["reference_data"]:
					if ref["url"] == mod["original_url"]:
						ref["url"] = PDF_BASE_PATH+mod["pdf"]
						ref["name"] = PDF_BASE_PATH+mod["pdf"]
else:
	print('Nothing to do, really....')
print(F'Writing JSON data to file: {JSON_DIR+MOD_JSON}')
with open(JSON_DIR+MOD_JSON, 'w') as f:
						json.dump(data, f, indent=2)
						f.close()
#validate json before replacing original
print(F'Validating file: {JSON_DIR+MOD_JSON}')
with open(JSON_DIR+MOD_JSON, 'r') as json_file:
	if json.load(json_file):
		print(F'OK: valid json file detected.')
		#replace original
		print(F'Replacing original JSON file:{JSON_DIR+SOURCE_JSON}')
		shutil.copy2(JSON_DIR+MOD_JSON, JSON_DIR+SOURCE_JSON)
	else:
		print(F'ERROR: invalid json file detected.')
