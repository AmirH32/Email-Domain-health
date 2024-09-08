import dns.resolver
import socket
import smtplib
import socket
import requests

def mx_lookup(domain):
    """
    Purpose: Looks up the MX records for the domain, if MX record has no servers then there is no mailserver or emails

    Outputs: First output is whether an MX record exists for the domain, the second output is the IP addresses for these MX servers if they exist
    """
    ip_addresses = set()  # Ensure ip_addresses is defined before use

    try:
        # Query the MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        print(f"MX records for {domain}:")
        for record in mx_records:
            mail_server = str(record.exchange).rstrip('.')
            if mail_server:
                pass
            else:
                continue
            try:
                # Resolve the mail server domain name to an IP address
                ip_address = socket.gethostbyname(mail_server)
                print(f"{' '*3}IP address: {ip_address}")
                ip_addresses.add(ip_address)
            except Exception as e:
                print(e)
                return False, None
    except Exception as e:
        print(e)
        return False, None
    
    return True, ip_addresses

def blacklist_checker(ip_addresses):
    """
    Checks if the ip address is blacklisted by any authority servers, if it is it's likely its emails are down/not in use
    """
    # Reverse the IP address for DNSBL lookup
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']  # Use Google's DNS server

    # List of authorities to see if the IP address is blacklisted
    dnsbls = dnsbls = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "uribl.zeustracker.abuse.ch",
    "uceprotect3.org",
    "mx.talktalk.net",
    "cbl.abuseat.org",
    "spam.dnsbl.sorbs.net",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "uceprotect3.dnsbl.org",
    'uceprotect2.org'
    'uceprotect3.org'
    ]
    # intialises list of blacklisted domains
    blacklisted = set()
    
    for ip_address in ip_addresses:
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        for dnsbl in dnsbls:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                # Perform DNS query to check if IP is listed as blacklisted
                resolver.resolve(query, 'A')
                blacklisted.add(dnsbl)
            except dns.resolver.NXDOMAIN:
                # IP not found in this DNSBL
                continue
            except dns.resolver.Timeout:
                print(f"DNS query timed out for {query}")
            except Exception as e:
                print(f"An error occurred during DNSBL lookup: {e}")

    return blacklisted
    
def check_dmarc_policy(domain):
    """
    Purpose: Checks if the dmarc exists and if the policy is set to block phishing or other emails (this should be set but some may not so not a great indicator)
    """
    try:
        # Query the DMARC record
        dmarc_query = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_query, 'TXT')
        
        # Process each record
        for answer in answers:
            record = str(answer).strip('"')
            if 'p=' in record:
                policy = record.split('p=')[1].split(';')[0].strip().lower()
                if policy in ['quarantine', 'reject']:
                    return True, policy
        return True, None  # DMARC record found, but policy is not quarantine or reject
    except dns.resolver.NoAnswer:
        return False, None   # No DMARC record found
    except dns.resolver.NXDOMAIN:
        return False, None  # Domain does not exist
    except Exception as e:
        print(f"Error occured:{e}")
        return False, None # Other errors

def spf_lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 12 # Set the lifetime (timeout) for the query
    resolver.timeout = 3 # Set the timeout per retry (usually a fraction of lifetime)
    try:
        # Query the TXT records for the domain
        txt_records = resolver.resolve(domain, 'TXT')
        spf_records = []
        for record in txt_records:
            for txt in record.strings:
                txt_str = txt.decode()
                if txt_str.startswith('v=spf1'):
                    spf_records.append(txt_str)
        
        if spf_records:
            return True
        else:
            return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        print("domain doesn't exist")
        return False
    except Exception as e:
        return False



def reverse_dns_lookup(ip_address):
    try:
        # Perform reverse DNS lookup
        domain_name = socket.gethostbyaddr(ip_address)[0]
        print(f"Reverse DNS for {ip_address}: {domain_name}")
        return domain_name
    except socket.herror:
        print(f"No reverse DNS entry found for {ip_address}.")
        return None
    except Exception as e:
        print(f"An error occurred during reverse DNS lookup: {e}")
        return None

    


def API_lookup(domain):
    headers = {
        'x-rapidapi-key': "dc34208faamsh143089f88dae999p1e505djsn277e0ed24adf",
        'x-rapidapi-host': "email-domain-checker1.p.rapidapi.com"
    }
    response = requests.get(f"https://email-domain-checker1.p.rapidapi.com/checkDomain/?domain={domain}", headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()  # Assuming the response is JSON
        if data['message'] == f"{domain} is a valid email domain":
            return True
    else:
        print(f"Request failed with status code: {response.status_code}")
        return False
    
def check_domain_resolution(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    
def check_remote_connection(url):
    try:
        response = requests.get(url, timeout=10)  # 10 seconds timeout
        # Check if the response status code indicates success (200-299)
        if response.status_code >= 200 and response.status_code < 300:
            return True
        else:
           return False
    except requests.exceptions.RequestException as e:
        return False



def main():
    # Scores how likely email server is down

    domains = ["gmx.co.uk", "zoho.com", "cantab.net", "fsmail.net", "madasafish.com", "tesco.net", "homecall.co.uk", "tinyworld.co.uk", "windowslive.com", "manx.net", "lineone.net", "tiscali.co.uk", "protonmail.com", "zen.co.uk", "dxc.com", "yahoo.com.sg", "libero.it"]
    for domain in domains:
        score = 0 
        mx_test, ip_addresses = mx_lookup(domain)
        if not mx_test:
            # If there is no mail server then email services are most likely down
            score += 3
            print("EMAIL DOES NOT EXIST - RED")
            continue

        # blacklisted = blacklist_checker(ip_addresses)
        # print("Blacklisted by:")
        # for dnsbl in blacklisted:
        #     print(dnsbl)
        #     score += 3

        dmarc_test, policy = check_dmarc_policy(domain)
        if not dmarc_test:
            print("No DMARC record")
            score += 3
        if not policy: 
            print("No DMARC policy")
            score += 1
        
        if not spf_lookup(domain): 
            print("NO SPF")
            score += 2

        if not check_domain_resolution(domain):
            print("Domain can't be resolved")
            score += 3
        
        if not check_remote_connection(f"http://{domain}"):
            print("Failed remote connection")
            score += 3
        
        # if ip_addresses:
        #     for ip_address in ip_addresses:
        #         reverse_dns_lookup(ip_address)
        
        if score >= 3:
            print("=== EMAIL DOES NOT EXIST - RED ===")
        elif score == 1:
            print("=== EMAIL is YELLOW (likely to exist) ===")
        elif score == 2:
            print("=== EMAIL is ORANGE (likely to not exist) ===")
        else:
            print("=== EMAIL is valid - GREEN ===")

        


main()
