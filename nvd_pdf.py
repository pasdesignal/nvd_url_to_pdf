#!/usr/bin/python3

import os
import json
import hashlib
import urllib.request
import shutil
from PyPDF2 import PdfFileReader, PdfFileWriter
import pdfkit
import time
import multiprocessing
import sqlite3 as sl

#1. generate copy of json file - DONE
#1. create list of all "Vendor Advisory" URLs from json file - DONE
#2. get PDF scrape of all URLs in list - DONE
#3. create new file name for each pdf based on hash of pdf file - DONE
#5. replace original URL in json file with new URL - DONE
#6. replace original json file - DONE
#7. timeout around sub thread for pdfkit call - DONE
#8. object oriented version
#9. Parallel processes for faster processing of json file
#10. split out functions into different services:
#               download/landing of modified.json and downloading of pdfs 
#               watchdog replacing urls in modified.json with existing pdfs 

JSON_SOURCE_DIR = './json/'
JSON_DEST_DIR = '/Users/pasdesignal/data/cves/'
PDF_DIR = '/Users/pasdesignal/data/cves/pdfs/'
SOURCE_JSON = 'nvdcve-1.1-modified.json'
MOD_JSON = 'nvdcve-1.1-modified.json.working'
PDF_BASE_PATH = 'http://127.0.0.1/pdfs/'
TAG_SELECTOR = ['Vendor Advisory', 'Expoit',]	#only convert urls tagged with these selectors
TAG_IGNORE = ['Mailing List', 'Broken Link']	#only convert urls tagged with these selectors
SCORE_SELECTOR = 5 								#only retrieve pdfs with a CVSS score of this or higher
URL_LIST = [] 									#list of dicts of cves extracted from json according to tags
MOD_LIST = [] 									#list of dicts, only if the url was replaced by pdf
TIMEOUT=10

#before all else, test directories exist etc
if os.path.isdir(JSON_SOURCE_DIR) != True:
	os.mkdir(JSON_SOURCE_DIR)
	os.chown(JSON_SOURCE_DIR, -1,-1) #change this to uid,guid numeric values of root, apache
	os.chmod(JSON_SOURCE_DIR, '0660')
if os.path.isdir(JSON_DEST_DIR) != True:
	os.mkdir(JSON_DEST_DIR)
	os.chown(JSON_DEST_DIR, -1,-1) #change this to uid,guid numeric values of root, apache
	os.chmod(JSON_DEST_DIR, '0660')
if os.path.isdir(PDF_DIR) != True:
	os.mkdir(PDF_DIR)
	os.chown(PDF_DIR, -1,-1) #change this to uid,guid numeric values of root, apache
	os.chmod(PDF_DIR, '0660')

def db_init():
	con = sl.connect('cve_pdfs.db')
	with con:
		con.execute("""
			CREATE TABLE PDFS (
			sourceUrl TEXT,
			name TEXT,
			);
			""")
	return(con)

def db_write(data):
	sql = 'INSERT INTO PDFS (name,sourceUrl) values(?, ?)'
	with con:
		result = con.executemany(sql, data)
		return(result)

def test_url(url, alreadyDone):
	print(F'Testing URL: {url}')
	if len(alreadyDone) > 0:
		for done in alreadyDone:
			if url in done["sourceUrl"]:
				print(F'ACHTUNG: already go this one bro: {url}')
				status_code=666
				return(status_code, done["pdf"])
	pdf="none"
	response = urllib.request.urlopen(url, timeout=5)
	status_code = response.getcode()
	return(status_code, pdf)

def get_pdf(url, q):
	print(F'Attempting to convert URL {url} to pdf...')
	pdf=''
	try:
		options = {'quiet': ''}
		pdf = pdfkit.from_url(url, False, options=options)
		print('Success.')
	except Exception as error:
		print ('Failed.')
	q.put(pdf)

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
	fout = open(pdf, 'ab') 					#ab is append binary; if you do wb, the file will append blank pages
	writer.write(fout)
	fout.close()
	print(F'Completed metadata append.')

def get_processed(pdf_dir):
	SUB_PROCESSED = []
	existing_pdfs = os.listdir(pdf_dir)
	if len(existing_pdfs) > 0:
		for file in existing_pdfs:
			if file.endswith(".pdf"):
				metadata = meta_pdf_read(pdf_dir+file)
				if "/sourceUrl" in metadata:
					print(F'sourceUrl found: {metadata["/sourceUrl"]}')
					_dict={"sourceUrl":metadata["/sourceUrl"], "pdf":pdf_dir+file}
					SUB_PROCESSED.append(_dict)
					db_write(_dict)
	else:
		print(F'No existing pdfs found in {pdf_dir}')
	return(SUB_PROCESSED)


con = db_init()

#main
alreadyDone = get_processed(PDF_DIR) 									#check existing pdfs so we dont process them again...
if os.path.isfile(JSON_SOURCE_DIR+SOURCE_JSON):							#extract URLs from json based on tags
	shutil.copy2(JSON_SOURCE_DIR+SOURCE_JSON, JSON_SOURCE_DIR+MOD_JSON)
	with open(JSON_SOURCE_DIR+MOD_JSON, 'r') as json_file:
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
	print(F'ERROR: file not found - {JSON_SOURCE_DIR+SOURCE_JSON}')
	print('Cannot continue.')
	exit()

#scrape URLs for content, create PDFs
if len(URL_LIST) > 0:
	for url in URL_LIST:
			try:
				_url=url["original_url"]
				response, response_pdf = test_url(_url, alreadyDone)
				if response == 200:
					#sub thread goes here
					q_worker = multiprocessing.Queue()
					proc = multiprocessing.Process(target=get_pdf, args=(_url, q_worker))
					proc.start()
					try:
						pdf = q_worker.get(timeout=TIMEOUT)
					except multiprocessing.queues.Empty:
						proc.terminate()
						print(F'ERROR: Timeout converting url: {_url}')
						pdf=''					
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
						print(F'ERROR: zero sized pdf object returned: {pdf}')
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
print(F'Writing JSON data to file: {JSON_SOURCE_DIR+MOD_JSON}')
with open(JSON_SOURCE_DIR+MOD_JSON, 'w') as f:
						json.dump(data, f, indent=2)
						f.close()
#validate json before replacing original
print(F'Validating file: {JSON_SOURCE_DIR+MOD_JSON}')
with open(JSON_SOURCE_DIR+MOD_JSON, 'r') as json_file:
	if json.load(json_file):
		print(F'OK: valid json file detected.')
		#replace original
		#print(F'Replacing original JSON file:{JSON_DIR+SOURCE_JSON}')
		shutil.copy2(JSON_SOURCE_DIR+MOD_JSON, JSON_DEST_DIR+SOURCE_JSON)
	else:
		print(F'ERROR: invalid json file detected.')
