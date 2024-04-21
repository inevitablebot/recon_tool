import subprocess
import sys
import os
import time

def execute_command_in_new_terminal(command):
    subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command}; read -p "Press enter key to close"'])
os.system("clear")
def slowprint(s):
		for c in s + '\n' :
			sys.stdout.write(c)
			sys.stdout.flush()
			time.sleep(10 / 1000)

try:
    running = True
    while running:
        slowprint('''\033[93m

 _                  _ _        _     _      _           _   
(_)_ __   _____   _(_) |_ __ _| |__ | | ___| |__   ___ | |_ 
| | '_ \ / _ \ \ / / | __/ _` | '_ \| |/ _ \ '_ \ / _ \| __|
| | | | |  __/\ V /| | || (_| | |_) | |  __/ |_) | (_) | |_ 
|_|_| |_|\___| \_/ |_|\__\__,_|_.__/|_|\___|_.__/ \___/ \__|

                                    ''')
        time.sleep(0.3)

        slowprint('''
            \033[92m
            RECON

            [01] whois
            [02] nslookup
            [03] theHarvester
            [04] subfinder(fast)
            [05] dnsenum
            [06] amass
            [07] enum4linux
            [08] sublist3r
            [09] spiderfoot
            [10] sslscan
            [11] nmap
            [12] wig(waf/cms)
            [13] httpx
            [14] dnsmap
            [15] dnsrecon
            [16] dig
            [17] masscan
            [18] Netdiscover
            [19] lbd
            [20] dmitry
            [21] subfinder(find all)
            ''')
        time.sleep(0.2) 
        select = input("Select any option :  ")
        if select == '1':
            whourl = input("\033[91mEnter the URL for whois: ")
            if not whourl:
                print("No URL provided.")
            else:
                execute_command_in_new_terminal(f"whois {whourl}")
        elif select == '2':
        	nsdomain = input("\033[91mEnter the domain for nslookup : ")
        	if not nsdomain:
        		print("No domain provided.")
        	else:
        		execute_command_in_new_terminal(f"nslookup {nsdomain}")
        elif select == '3':
        	harvester_domain=input("\033[91menter domain for theHarvester: ")
        	if not harvester_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"theHarvester -d {harvester_domain} -b all")
        elif select == '4':
        	subdomain=input("\033[91menter domain to find subdomain:")
        	if not subdomain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"subfinder -d {subdomain}")
        elif select =='5':
        	dns_domain = input("\033[91menter domain for dnsenum: ")
        	if not dns_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"dnsenum {dns_domain} ")
        elif select == '6':
        	amass_domain=input("\033[91menter domain for amass : ")
        	if not amass_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"echo -e '\033[91mIn Progress please wait.... \033[0m' &&  amass enum -d {amass_domain} -brute -active && amass inte -org  ") 
        elif select == '7':
        	enum_domain=input("\033[91menter domain for enum: ")
        	if not enum_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"enum4linux -a {enum_domain}")
        elif select == '8':
        	sub_domain=input("\033[91menter domain to find subdomain: ")
        	if not sub_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"sublist3r -d {sub_domain} ")
        elif select == '9':
        	spider_domain=input("\033[91mprovide domain for scan :")
        	if not spider_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"spiderfoot -s {spider_domain}")
        elif select =='10':
        	ssl_domain=input("\033[91menter domain for ssl scan:")
        	if not ssl_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"sslscan {ssl_domain} ")
        elif select == '11':
        	nmap_ipdm=input("\033[91menter ip or domain to scan  : ")
        	if not nmap_ipdm:
        		print("no ip/domain provided ")
        	else:
        		execute_command_in_new_terminal(f"echo -e '\033[91mIn Progress please wait.... \033[0m' && nmap {nmap_ipdm} &&echo -e '\033[93mFor more detailed output run sudo nmap -Pn -sS -SV (ip/domain) \033[0m'")
        elif select == '12':
        	waf_url = input("\033[91minput url to scan for waf/cms: ")
        	if not waf_url:
        		print("no url provided")
        	else:
        		execute_command_in_new_terminal(f"wig -v {waf_url}")
        elif select == '13':
        	httpx_url=input("\033[91menter url to get info:  ")
        	httpx_method=input("enter the method [GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD ] : ")
        	if not httpx_url:
        		print("no url provided")
        	else:
        		execute_command_in_new_terminal(f"httpx -m {httpx_method} {httpx_url}")
        elif select == '14':
        	dnsmap_domain=input("\033[91menter domain for dnsmaping : ")
        	if not dnsmap_domain:
        		print("no domain provided")
        	else:
        		execute_command_in_new_terminal(f"dnsmap {dnsmap_domain}")
        elif select == '15':
        	dnsrecon_domain=input("\033[91menter domain to recon dns info: ")
        	if not dnsrecon_domain:
        		print("no domain provided ")
        	else:
        		execute_command_in_new_terminal(f"dnsrecon -d {dnsrecon_domain}")
        elif select == '16':
        	dig_url=input("\033[91menter ip/domain :")
        	if not dig_url:
        		print("no ip/domain provided")
        	else:
        		execute_command_in_new_terminal(F"dig {dig_url}")
        elif select == '17':
        	masscan_ip=input("\033{enter ip :")
        	if not masscan_ip:
        		print("no ip provided")
        	else:
        		execute_command_in_new_terminal(f"masscan -p0-65535 {masscan_ip}")
        elif select == '18':
        	execute_command_in_new_terminal(f"arp-scan --localnet ")
        	execute_command_in_new_terminal(f" netdiscover")
        elif select == '19':
        	lbd_domain=input("\033[91menter domain for load-balancing test : ")
        	if not lbd_domain:
        		print("no domain provided ")
        	else:
        		execute_command_in_new_terminal(f"lbd {lbd_domain}")
        elif select == '20':
        	dmitry_domain=input("\033[91menter domain")
        	if not dmitry_domain:
        		print("no domain provided ")
        	else:
        		execute_command_in_new_terminal(f"dmitry {dmitry_domain}")
        elif select == '21':
        	suball_domain=input("\033[91menter domain to full scan")
        	if not suball_domain:
        		print(" no domain provided")
        	else:
        		execute_command_in_new_terminal(f"subfinder -all -d {suball_domain} -v ") 	
except KeyboardInterrupt:
    print("\n\033[91m [-] Exiting.....")
    time.sleep(1)
    os.system("clear")
    print("\033[97m [*] Thank You.....")
    time.sleep(1)
    sys.exit()
