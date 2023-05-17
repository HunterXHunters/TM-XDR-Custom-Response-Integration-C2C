# TM-XDR-Custom-Response-Integration-C2C
End-to-End Event-Driven Automation for observed Command and Control (C2C) alerts and hunting for un-discoved entities.

In this script, we have picked **Mitre Tactic Id: TA0011** which points to Command and Control attacks for all techniques associated and this can help you to automate manual tasks which L1 team performing in process of triaging the alert.

1. Script fetches all Critical/ High alerts and picks first alert associated with Tactic Id: TA0011 from observed attack techniques alert for last 10 days [You can change the days from timepicker in the script] and extracts meta-data required for analysis. 

2. From alert, script pulls value form Suspicious Highlighted objects and send it VirusTotal for reputation checks.

3. From VirusTotal results, script checks the below use-cases [you can always fine-tune the conditions for count of VT engines detections]:
#### Use-cases:
	1. If number of engines detected is 0: is not Malicious and needs no furthure actions.
	2. If number of engines detected is > 0 and <= 3: Maybe Malicious which requires manual investigation and if found abnormal, please add findings to VisionOne Suspicious Object list or add IoC to your respective security tools [if non-TM tools at Network, Email Gateway, etc.]
	3. If number of engines detected is > 4: is found Malicious and next steps follows as below.

4. If number of engines detected is > 4, we will now send the Suspicious Highlighted objects to Intezer Analze Sandbox environment.

5. From sandbox results, script now checks for below use-cases:
#### Use-case 1:
	- If risk score is good, this requires Manual Assessment as VirusTotal reputation is Bad but Sandbox analysis finds no suspicious indicators
	- If risk score if bad: Script triggers Vision One Threat Intelligence module and block below indicators in Suspicious Object Management:
		 * Domain 
		 * URL and
		 * IP addresses
#### Use-case 2:
	- If in case of Short-lived URLs: The URL you entered seems to be offline and analysis of offline URLs is currently unsupported. Script triggers Vision One Threat Intelligence module and block below indicators in Suspicious Object Management:
		* Domain 
		* IP addresses

Important: Malicious URLs tend to have a short lifespan. The fact that this URL is offline is highly suspicious.
		
6.	As part of Threat Hunting to discover un-detected entities to above discovered Highlighted objects and to this, 
	- script constructs STIXs feed with suspicious domain.
	- Constructed STIXs feed gets auto uploaded to custom Threat Intelligence Reports and initates auto-sweeping task to detect all entities with observed indicator.

![observed_attack_techniques](https://github.com/HunterXHunters/TM-XDR-Custom-Response-Integration-C2C/assets/2347778/06885012-d6f8-406e-ae99-9d3127419e25)

In this script, we have used below Trend Micro Vision One modules for this automation.

#### Observed Attack Techniques:
Displays the individual events detected in your environment that may trigger an alert and any related MITRE information.

#### Suspicious Object Management:
You can manage the Suspicious Object List and Exception List to control the specific information for synchronization.

#### Threat Intelligence Reports:
The Intelligence Reports app allows you to leverage valuable indicators of potential threats from both curated intelligence reports and your custom intelligence reports.

