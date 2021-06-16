import pdfkit
import os.path
import json
import hashlib
import urllib.request

TEST_JSON = 'cves2.json'
TEST_URL = 'https://mapserver.org/development/changelog/changelog-7-4.html'
TEST_OUT_FILE = 'test.pdf'
TEST_URL_BASE_PATH = 'http://opencve.local/pdfs/'
URL_LIST = []
PDF_LIST = []

def test_url(url):
	print(F'Testing URL: {url}')
	response = urllib.request.urlopen(url)
	status_code = response.getcode()
	print(status_code)
	return(status_code)

def get_pdf(url):
	print(F'Attempting to convert URL {url} to pdf...')
	pdf = pdfkit.from_url(url, False)
	return(pdf)
	
#1. generate copy of json file
#1. create list of all "Vendor Advisory" URLs from json file
#2. get PDF scrape of all URLs in list
#3. create new file name for each pdf based on hash of pdf file
#4. generate new URL for each pdf
#5. replace original URL in json file with new URL
#6. replace original json file

#test json file exists
if os.path.isfile(TEST_JSON):
	with open(TEST_JSON) as json_file:
		data = json.load(json_file)
		for cve in data["CVE_Items"]:
			#print(F'ID: {cve["cve"]["CVE_data_meta"]["ID"]}')
			for ref in cve["cve"]["references"]["reference_data"]:
				if "Vendor Advisory" in ref["tags"]: 
					#print(F'ID: {cve["cve"]["CVE_data_meta"]["ID"]}')
					#print(F'URL: {ref["url"]}')
					URL_LIST.append(ref["url"])
else:
	print(F'ERROR: file not found - {TEST_JSON}')
if len(URL_LIST) > 0:
	for url in URL_LIST:
		try:
			url_test = test_url(url)
			if url_test == 200:
				pdf = get_pdf(url)
				if len(pdf) > 0:
					pdf_md5 = hashlib.md5(pdf).hexdigest()
					print(F'MD5 hash of pdf: {pdf_md5}')
					file_name=pdf_md5+".pdf"
					with open(file_name, 'wb') as f:
						f.write(pdf)
						f.close()
					if os.path.isfile(file_name):
						PDF_LIST.append(file_name)
				else:
					print(F'ERROR: zero sized pdf object: {pdf}')
			else:
				print(F'URL response bad: {url}')
		except Exception as error:
			print(F'ERROR: {error}')

#display results:
print(URL_LIST)
print(F'URL count: {len(URL_LIST)}')
print(PDF_LIST)
print(F'PDF count: {len(PDF_LIST)}')




