import requests
import json
import time
from datetime import datetime, timedelta

requests.packages.urllib3.disable_warnings()  # Disable MISP SSL warnings as value is set to false

url_base = "https://api.xdr.trendmicro.com" # VisionOne URL
oat_path = "/v3.0/oat/detections" # Workbench Alert API 
suspiciousObjects_path = "/v3.0/threatintel/suspiciousObjects" #Suspicious Object Path

#VisionOne API Token
token = "Your_VisionOne_API_Token"

# Virustotal API
vtapi_key = "Your_VirusTotal_API_Token"
vturl = "https://www.virustotal.com/vtapi/v2/url/report"

#Intezer Analysis: Sandbox 1
Intezerurl = "https://analyze.intezer.com/api/v2-0/url"
JWT_token = "Your_Intezer_Alalyzis_Sandbox_API_Token"

# Import STIX Format to TM Intelligence Reports for auto-sweeping as part of Threat Hunting

url_stixpath = '/v2.0/xdr/threatintel/intelligenceReports'

######################################################### TimePicker ##############################################################################
# Date & Time Picker to fetch alerts from specific period
        
d = datetime.now() #gets Todays time
endDate= d.strftime("%Y-%m-%dT%H:%M:%SZ") #Keeping todays date as EndDate and Converting to ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) 
new_startDate = d - timedelta(days=10)    # Deduction -10 days to create Start date i.e. Datetime between "startDateTime" and "endDateTime" is 10 days to be used for retrieving alert data.
startDate = new_startDate.strftime("%Y-%m-%dT%H:%M:%SZ") # Converting StartDate to ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) 
######################################################### End of TimePicker ##############################################################################


##############################################Function for constructing STIX Format ####################################################################################

def say_tmSTIX():
    bundle = {
    "type": "bundle",
    "id": "bundle--5b7ebfbe-dcf0-476d-b389-f2c3880fbbg9",
    "objects": [
        {
            "type": "identity",
            "id": "identity--aedd741c-d836-4ca9-9fd4-e541e3ec5009",
            "name": "SaiCharan P",
            "created": "%s" %eventTime,
            "modified": "%s" %endDate,
            "spec_version": "2.1"
        },
        {
            "created_by_ref": "identity--aedd741c-d836-4ca9-9fd4-e541e3ec5009",
            "name": "%s"%Suspicious_HostName,
            "published": "%s" %eventTime,
            "modified": "%s" %endDate,
            "report_types": [
                "indicator"
            ],
            "object_refs": [
                "identity--aedd741c-d836-4ca9-9fd4-e541e3ec5009",
                "indicator--69c17561-81fc-411e-ad42-75c36dee9328"
            ],
            "type": "report",
            "id": "report--e0070c44-2bcc-415d-a031-f12ba1febf68",
            "created": "%s" %endDate,
            "spec_version": "2.1"
        },
        {
            "valid_from": "%s" %eventTime,
            "created_by_ref": "identity--aedd741c-d836-4ca9-9fd4-e541e3ec5009",
            "created": "%s" %endDate,
            "pattern": "[domain-name:value = '%s']"%Suspicious_HostName,
            "pattern_type": "stix",
            "labels": [
                "malicious-activity, C2C, Tactic ID: TA0011"
            ],
            "modified": "%s" %endDate,
            "type": "indicator",
            "id": "indicator--69c17561-81fc-411e-ad42-75c36dee9328",
            "spec_version": "2.1",
            "description": ""
        }
    ]
}
    # Saving the above above STIX Json to maldomainstix.json file
    
    jsonFile = open("maldomainstix.json", "w")
    jsonFile.write(json.dumps(bundle))
    jsonFile.close()
    
    ### Extracting Report ID from STIX, where this ID will be used in Threat Hunting during auto-sweeping task
    stixid = "report--e0070c44-2bcc-415d-a031-f12ba1febf69"
    stix_id_format = bundle["objects"][1]["id"]
    #print (stix_id_format)
    
    return stix_id_format   
    
##########################################################End of STIIX Format###############################################################################


###############################Function to upload the STIXs Feed and Initate auto-sweeping task for Threat Hunting###############################################################################

def upload_TMIntent():

    stix_query_params = {}
    headers = {'Authorization': 'Bearer ' + token}

    data = {'format': 'stix',
        'reportName': 'Suscipicious URL',
        'fileName': 'Suspicious C2C URL'}
    # Please mention absolute path to your STIX feed in given below format:
    # Path: C:\\Users\\TrendMicro VisionOne\\maldomainstix.json
    files = {'file': ('maldomainstix.json', open('YOUR_ABSOLUTE_FILE_PATH', 'rb'))}

    r = requests.post(url_base + url_stixpath, params=stix_query_params, headers=headers, data=data, files=files)

    if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
        #print("success Uploaded "+ json.dumps(r.json(), indent=4))
        print("success Uploaded")
    else:
        print(r.text)

def auto_sweep():
    url_path = '/v3.0/threatintel/intelligenceReports/sweep'
    query_params = {}
    headers = {'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'}
    body = [{'id': stix_id_report_value,
         'sweepType': 'manual',
         'description': 'Auto-sweeping through Script)'}]

    r = requests.post(url_base + url_path, params=query_params, headers=headers, json=body)

    print(r.status_code)
    if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
        #print(json.dumps(r.json(), indent=4))
        return "Autosweeing Intiated"


####################################################Start of TM Observed Attack Technique Alert Analysis####################################################################

query_params = {'detectedStartDateTime': startDate,
    'detectedEndDateTime': endDate,
    'ingestedStartDateTime': startDate,
    'ingestedEndDateTime': endDate,
    'top': '1'}
headers = {'Authorization': 'Bearer ' + token, 'TMV1-Filter': "(riskLevel eq 'high' or riskLevel eq 'critical') and filterMitreTacticId eq 'TA0011' "}
# riskLevel eq 'high' and filterName eq 'Malicious URL' and filterMitreTacticId eq 'TA0011' filterMitreTechniqueId eq 'T1071.001' 
r = requests.get(url_base + oat_path, params=query_params, headers=headers)

#print(r.status_code)

if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
    #print(json.dumps(r.json(), indent=4))
    oat_alert = json.dumps(r.json(), indent=4)
    # serializing the values 
    data = json.loads(oat_alert)

    #Detection Filter
    if data['items'][0]['filters'][0]['name'] == "Malicious URL":
        print("\nWe are analyzing C2C alert named 'Malicious URL' \n\n "+ data['items'][0]['filters'][0]['description'])
        print("")
        
        #######------ Observed Attack Technique to get Highlighted URLs/IOCs ------#######
        print ("++++++++++++++++++++++++ ATTACK INFORMATION ++++++++++++++++++++++++ \n \n")
        
        eventName = data['items'][0]['detail']['eventName'] #Event Name
        Detection_filter_risk_level = data['items'][0]['detail']['filterRiskLevel'] #Detection Filter Risk Level
        endpointHostName = data['items'][0]['detail']['endpointHostName'] #Affected HostName
        endpointIp = data['items'][0]['detail']['endpointIp'] #Affected Host IP Address
        ruleName = data['items'][0]['detail']['ruleName'] # Detection Rule Name
        eventTime = data['items'][0]['detail']['rt_utc'] # Detection Time
        
        print ("Affect hostname: %s"%endpointHostName + " %s" %endpointIp + "\nRisk Level: %s"%Detection_filter_risk_level  
        + "\nEvent Name: %s" %eventName + "\nRule Name: %s" %ruleName + "\nEvent Detection Time: %s" %eventTime)
       
       ####---- Suspicious Highlighted Request ----#####
        Suspicious_HostName = data['items'][0]['detail']['hostName'] #Suspicious Host to be analyzed
        print (Suspicious_HostName)
        highlightedRequest = data['items'][0]['detail']['request'] 
        print ("Suspicious Request Detected: %s" %highlightedRequest) #Suspicious Request to be analyzed
        
        ###---- Sending Highlighted Requests to VirusTotal ----###
        print ("\n \n++++++++++++++++++++++++ Submiting Suspicious Request to ThreatIntel: VirusTotal ++++++++++++++++++++++++ \n")
            
        vtparams = {'apikey': vtapi_key, 'resource': highlightedRequest}
        response = requests.get(vturl, params= vtparams) 
        response_json = json.loads(response.content)
        #print (response_json)
        
        # Conditions to check for Score and number of detections
        
        if response_json['positives'] <= 0:
            print (response_json['resource']+' is Not Malicious and needs no furthure actions')
        
        elif response_json['positives'] <= 3:
            print (response_json['resource']+' Maybe Malicious which requires manual investigation and if found abnormal, please add findings to Suspicious Object list')
        
        elif response_json['positives'] > 3:
            x = response_json['resource']
            print (" %s"%x + " is found Malicious and next steps follows")
             
            ############ Submiting to Sandbox Environment for Analysis ############            
            ##### Tool 1: Intezer Analze
            print ("\n \n++++++++++++++++++++++++ Submiting URL to Sandbox Environment: IntezerAnalyze ++++++++++++++++++++++++ \n")
            print(x)
            payload = {"url": "%s"%x} #URL to be scaned
            headers_params = {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer "+JWT_token
                       }
                       
            ############ Submiting URL to Sandbox environment   ##############         
            try:
                intezerAnalze_response = requests.request("POST", Intezerurl, json=payload, headers=headers_params)
                analysis_id_response = json.dumps(intezerAnalze_response.json(), indent=4)
                data = json.loads(analysis_id_response)
                analysis_id = data['result_url']
                
                print("URL submitted sucessfully and analysis is in progress, please wait for 20 seconds")
                time.sleep(20)
     
                # Get Analysis Report by analysis_id

                GetAnalysis_url = "https://analyze.intezer.com/api/v2-0/%s"%analysis_id
                intezer_analysis_response = requests.request("GET", GetAnalysis_url, headers=headers_params)
                intezer_analysis_res = json.dumps(intezer_analysis_response.json(), indent=4)
                data = json.loads(intezer_analysis_res)
                #print (data)
                intaz_riskScore = data['result']['api_void_risk_score']
                intaz_scanned_url = data['result']['scanned_url']
                intaz_ip = data['result']['ip']
                intaz_summary_title = data['result']['summary']['title']
                intaz_summary_description = data['result']['summary']['description']

                print("Scanned URL: %s"%intaz_scanned_url + " and DNS Record %s"%intaz_ip)

                print ("APIVoid Risk Score: %s"% intaz_riskScore)

                print("Summary: \n %s"%intaz_summary_title +"\n %s"%intaz_summary_description)
                
                # Condition to check Sandbox Summary title for Risk #
                
                if intaz_summary_title == 'No Threats':
                    print("Requires Manual Assessment as VirusTotal Reputation is Bad but Sandbox analysis finds no suspicious indicators")

                elif intaz_summary_title == 'Malicious URL':
                    print("Follow-up actions to block domain and IP addresses in VisionOne Threat Intelligence Module")
                    # Add to Block List: Block Hostname, URL and IP in Suspicious Object Management in Threat Intelligence
                    
                    headers_som = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json;charset=utf-8'}
                    IP_body = [{'domain': Suspicious_HostName, 'description': 'Both Sandbox and VT Reputation is Bad','scanAction': 'block', 'riskLevel': 'high', 'daysToExpiration': '90'},
                            {'url': intaz_scanned_url, 'description': 'Both Sandbox and VT Reputation is Bad','scanAction': 'block', 'riskLevel': 'high', 'daysToExpiration': '90'},
                            {'ip': intaz_ip, 'description': 'Both Sandbox and VT Reputation is Bad','scanAction': 'block', 'riskLevel': 'high', 'daysToExpiration': '90'}
                    
                    ]
                    r = requests.post(url_base + suspiciousObjects_path, params=query_params, headers=headers_som, json=IP_body)
                    
                    print ("\n \n++++++++++++++++++++++++ Containment Stratergy ++++++++++++++++++++++++ \n\n")
                    time.sleep(2)
                    print("As part of containment stratergy, we are adding Host name, IP and URL to block list \n")
                    
                    print ("\n \n++++++++++++++++++++++++ Remediation Stratergy ++++++++++++++++++++++++ \n")
                    print("Perform basic host log analysis, run on-demand Anti-malware scan and raise ticket to L2 with your observations from logs along with scan results ")
                    
                    print ("\n \n++++++++++++++++++++++++ Threat Hunting Stratergy ++++++++++++++++++++++++ \n")
                
                    
                    #print("Formating in STIX format for XDR ThreatIntel")
                    stix_id_report_value = say_tmSTIX()
                    print(stix_id_report_value)
                
                    # print("\n \n Uploading to XDR Threat Intelligence")
                    upload_TMIntent()
                    print("\n \n Uploading Sucessfull to XDR Threat Intelligence")
                    # Intitating Auto-Sweeping task in Threat Intelligence for uploaded STIXs feed
                    auto_sweep()
                    print("\n \n Auto-Sweeping initiated for uploaded Feed in XDR Threat Intelligence")

            except:
                print("The URL you entered seems to be offline. Analysis of offline URLs is currently unsupported. \n Important: Malicious URLs tend to have a short lifespan. The fact that this URL is offline is highly suspicious. \n")
                # Block Hostname in Suspicious Object Management in Threat Intelligence
                #print("where is the %s"%Suspicious_HostName)
                headers_som = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json;charset=utf-8'}
                body = [ {'domain': Suspicious_HostName, 'description': 'VT Reputation is Bad and requested host now offline','scanAction': 'block', 'riskLevel': 'high', 'daysToExpiration': '90'},
                        {'url': highlightedRequest, 'description': 'VT Reputation is Bad and requested host now offline','scanAction': 'block', 'riskLevel': 'high', 'daysToExpiration': '90'}
                ]
                r = requests.post(url_base + suspiciousObjects_path, params=query_params, headers=headers_som, json=body)
                print ("\n \n++++++++++++++++++++++++ Containment Stratergy ++++++++++++++++++++++++ \n")
                time.sleep(2)
                print("As part of containment stratergy, we are adding Domain and URL to block list \n") 
                
                print ("\n \n++++++++++++++++++++++++ Remediation Stratergy ++++++++++++++++++++++++ \n")
                print("Perform basic host log analysis, run on-demand Anti-malware scan and raise ticket to L2 with your observations from logs along with scan results ")

                
                
                print ("\n \n++++++++++++++++++++++++ Threat Hunting Stratergy ++++++++++++++++++++++++ \n")
                
                
                #print("Formating in STIX format for XDR ThreatIntel")
                stix_id_report_value = say_tmSTIX()
                print(stix_id_report_value)
                
                # print("\n \n Uploading to XDR Threat Intelligence")
                upload_TMIntent()
                print("\nUploading Sucessfull to XDR Threat Intelligence")
                auto_sweep()
                print("\nAuto-Sweeping initiated for uploaded Feed in XDR Threat Intelligence")
                
                
                
            
        else:
            print("URL Not Found in VirusTotal")
            
        time.sleep(15)  
        
    else:
        print("This is not Malicious URL C2C alert")
    
else:
    print(r.text)
    

