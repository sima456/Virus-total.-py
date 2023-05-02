import re
import requests
import json
import time
requests.packages.urllib3.disable_warnings()

indicators = []
providers = []
container = []

def virustotal(ip):

	headers = {
	'x-apikey':'' #Write vt api key.
	}
	response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/'+ip,headers=headers, verify=False).json()
	harmless = response["data"]["attributes"]["last_analysis_stats"]["harmless"]
	malicious = response["data"]["attributes"]["last_analysis_stats"]["malicious"]
	suspicious = response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
	undetected = response["data"]["attributes"]["last_analysis_stats"]["undetected"]
	reputation = harmless + malicious + suspicious + undetected
	malscore = malicious + suspicious
	score = (str(malscore) + "/" + str(reputation))
	if malscore >= 2:
		verdict = "malicious"
	else:
		verdict = "not malicious"
	vt_verdict = {"provider":"virustotal","verdict": verdict, "score": score}
	return vt_verdict

def otx(ip):

	headers = {
	'X-OTX-API-KEY': '' #Write vt api key.
	}
	response = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/'+ip+'/general',headers=headers, verify=False).json()
	pulsecount = response["pulse_info"]["count"] #Reputation is not healthy at OTX. Therefore I check pulse info.
	#print (pulsecount)
	#print (response)
	verdict = ""
	if pulsecount >= 2:
		verdict = "malicious"
	if pulsecount == 1:
		verdict = "possible malicious"
	if pulsecount == 0:
		verdict = "not malicious"
	otx_verdict = {"provider":"otx","verdict": verdict, "pulse_count": pulsecount}
	return otx_verdict


def __main__():
	print ("Reputation checker started")
	f = open('logs.txt', 'r')
	o = f.read()
	ip1 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', o)
	verdict = ''
	removedup = [*set(ip1)]
	#removedup.remove('0.0.0.0')

	for i in removedup: 
		print ("Checking IP:"+i)
		vt_verdict = virustotal (i)
		otx_verdict = otx(i)
		providers = [vt_verdict,otx_verdict]		
		indicators.append({"value":i,"type":"ip","providers":providers})
		time.sleep(20) #Virustotal has a request limit. That's why I used sleep.
	container.append({"indicators":indicators})
	with open("output.json","w") as output:
		json.dump(container, output, indent=4,separators=(',',': '))

__main__()
