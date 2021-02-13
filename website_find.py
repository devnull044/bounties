import sys, requests, ipaddress
from requests.packages.urllib3.exceptions import InsecureRequestWarning

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"} #for burp
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_for_web(address, timeout):
	if '/32' in address or '/' not in address:
		ip = ipaddress.ip_address(address.strip('/32'))
		url_s = 'https://%s/' % ip
		url_ns = 'http://%s/' % ip
		r_s = requests.get(url=url_s, proxies=proxies, verify=False, timeout=timeout)
		r_ns = requests.get(url=url_ns, proxies=proxies, timeout=timeout)
		if r_s.status_code == 200:
			print("Website availible at:", url_s)
		if r_ns.status_code == 200:
			print("Website availible at:", url_ns)
	else:
		ips = ipaddress.ip_network(address)
		for x in ips.hosts():
			#print(x)
			url_s = 'https://%s/' % x
			url_ns = 'http://%s/' % x
			#print(url_s)
			#exit()
			try:
				r_s = requests.get(url=url_s, verify=False, timeout=timeout)
				r_ns = requests.get(url=url_ns, timeout=timeout)
			except:
				continue
			if r_s.status_code == 200:
				print("Website availible at:", url_s)
			else:
				continue
			if r_ns.status_code == 200:
				print("Website availible at:", url_ns)
			else:
				continue

def main():
	if len(sys.argv) != 3:
		print('(+) usage: %s <ip address/range> <timeout in seconds>' %sys.argv[0])
		print('(+) eg: %s 10.10.10.0/24 5' % sys.argv[0])
		sys.exit(-1)

	address = sys.argv[1].strip()
	timeout = int(sys.argv[2].strip())
	print("Scanning %s for sites" % address)
	check_for_web(address,timeout)

if __name__ == "__main__":
	main()
