import sys
import whois
import dns.resolver
import shodan
import requests
import socket
import argparse

""" start argparse """

argparse = argparse.ArgumentParser(description="This is a basic information gathering tool ." , usage="python info_gathering.py -d DOMAIN  [-i IP]")
argparse.add_argument("-d","--domain",help="Enter the domain name for footprinting .")  #For Domain
argparse.add_argument("-i","--shodan",help="Enter the IP for shodan search.")           #For IP
argparse.add_argument("-o","--output",help="Enter the file to wight output to.")                          #For Save Output



args=argparse.parse_args()
domain=args.domain
ip=args.shodan
output=args.output

""" End argparse """

"""Start Whois Module"""
whois_result=''
whois_result +='\n'
whois_result += "[+] Getting whois info..\n"
whois_result += "[+] whois info found..\n"
whois_result +='\n'

try:
    whois_info = whois.whois(domain)
    #print(py)
    whois_result +='\n'
    for i in whois_info:

        if i=="status":
            continue
        whois_result += f"[+] {i} : {whois_info[i]}\n"

except:
    whois_result +='\n'
    whois_result += "[+] WHOIS'S ERROR FOUND......\n"


print(whois_result)

"""End Whois Module"""




"""Start DNS Module"""

dns_result =''

all_record=['A','AAAA','PTR','NS','MX','SOA','CNAME','TXT']

dns_result += '\n'
dns_result += "[+] Getting DNS info..\n"
dns_result += "[+] DNS info found..\n"
dns_result += '\n'

for i in all_record:
    try:
        result = dns.resolver.resolve(domain, i)
        for val in result:
            dns_result += f'[+] {i} Record :  {val.to_text()}\n'
        dns_result += '\n'

    except:
        dns_result += f"[+] The DNS response does not contain an answer to the question: {domain}. IN {i}\n"
        dns_result +='\n'


print(dns_result)
"""End DNS Module"""



"""Start GEOLOCATION REQUESTS Module"""

geolocation_result =''


geolocation_result += '\n'
geolocation_result += "[+] Getting GEOLOCATION info..\n"
geolocation_result += "[+] GEOLOCATION info found..\n"
geolocation_result += '\n'

try:
    response = requests.get(f"https://geolocation-db.com/json/86f5f280-f4eb-11ec-8676-4f4388bc6daa/{domain}")
    text_value = response.text
    dic_value = eval(text_value)  # convert str to dic
    for i in dic_value:
        geolocation_result += f"[+] {i} : {dic_value[i]}\n"
    geolocation_result += '\n'
except:
    geolocation_result += '\n'
    geolocation_result += "[+] GEOLOCATION'S ERROR FOUND......\n"

print(geolocation_result)

"""End GEOLOCATION REQUESTS Module"""





"""Start SHODAN Module"""


if ip:
    shodan_result =''
    shodan_result += '\n'
    shodan_result += "[+] Getting info from SHODAN..\n"
    shodan_result += "[+] SHODAN info found..\n"
    shodan_result += '\n'
    api = shodan.Shodan("DaJBmwd78NjwHmkr6foNrbyB81MOCXKw")
    try:
        results = api.search(ip)
        shodan_result += f"[+] Result found : {results['total']}\n"
        shodan_result += '\n'
        count=1
        for result in results['matches']:
            shodan_result += f"[+] IP : {result['ip_str']}\n"
            shodan_result += f"[+] Data  : {result['data']} \n"
            count+=1
            if count==4:
                break
    except:
        shodan_result += '\n'
        shodan_result += "[+] SHODAN'S ERROR FOUND......\n"

    print(shodan_result)

"""End SHODAN Module"""



"""Start OUTPUT Module"""


if output:
    with open(output, 'a') as f:
        f.write(whois_result)
        f.write(dns_result)
        f.write(geolocation_result)
        f.write(shodan_result)

    f.close()

"""End OUTPUT Module"""
