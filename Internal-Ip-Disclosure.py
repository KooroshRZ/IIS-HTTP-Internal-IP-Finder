import re
import socket
import ssl
from colorama import Fore, Style, Back

# This exploit is inspired by metasaploit module "Microsoft IIS HTTP Internal IP Disclosure"
# But we try too cover more possible situiations
# Hosts list are in a format like this
# <prorocol>://<domain or IP address>:<port>
# For more info read the example-hosts.txt

# Input file

hosts_file = "C:\\Users\\k.rajabzadeh\\Desktop\\python\\IIS-Internal-IP-Finder\\my-hosts.txt"
hosts_list = open(hosts_file, 'r').readlines()


protocol = ''
server_name = ''
server_ip = ''
server_port = ''

# We need some 30* redirection to find the internal IP !
# These urls maybe cause a redirect

possible_iis_redirect_urls = [
    '/',
    '/aspnet_client',
    '/images',
    '/uploads',
    '/files',
    '/updatemanager',
    '/users'
]

# Our preference is HEAD
# But there may not be any route for HEAD method 
# So we try GET method too

http_methods = [
    'HEAD',
    'GET'
]

def enumerate_internal_IP_addresses():

    for host in hosts_list:
        
        if host == "\n" or host == '' or host[0] == "#":
            continue

        if host[len(host)-1] == "\n":
            host = host[:-1]

        protocol = host[ : host.find("://")]
        server_name = host[host.find("://") + 3 : host.find(":", 6)]
        server_port = int(host[host.find(":", 7) + 1 : ])

        # choose the url
        # looping through urls next time :)
        url = possible_iis_redirect_urls[1]

        regex_compiler = re.compile(r"^\d+\.\d+\.\d+\.\d+")

        if regex_compiler.match(server_name) == None:
            try:
                server_ip = socket.gethostbyname(server_name)
                print(Fore.LIGHTCYAN_EX + "* Host {}:{} resolved to IP {}:{}".format(server_name, server_port, server_ip, server_port) + Style.RESET_ALL)
            except:
                print(Back.LIGHTRED_EX)
                print("    [-] Error on resolving the host {}".format(server_name))
                print(Style.RESET_ALL)
                continue
        else:
            server_ip = server_name
        
        
        if protocol == 'http':

            for method in http_methods:

                try:
                    sock_http = socket.create_connection((server_name, server_port))
                except:
                    print(Back.LIGHTRED_EX)
                    print("    [-] Error on connecting to host {}:{}".format(server_name, server_port))
                    print(Style.RESET_ALL)
                    sock_http.close()
                    continue

                request = "{} {} HTTP/1.0\r\nConnection: close\r\n\r\n".format(method, url)
                sock_http.sendall(request.encode())

                response = ''
                recv = sock_http.recv(1024).decode()
                response += recv

                if response != '' and response.find("Location") > -1 and response.find("http") > -1:
                    
                    tmp_index_1 = response.find("http")
                    # flag = 0
                    # if tmp_index_1 == -1:
                    #     tmp_index_1 = response.find("http://")
                    #     flag -= 1
                    
                    tmp_index_2 = response.find(url, tmp_index_1)

                    location = response[ tmp_index_1: tmp_index_2 ]

                    if regex_compiler.match(location[7 :]) == None:
                        print(Fore.LIGHTYELLOW_EX)
                        print("    [!] Redirectoin found with location header but does not contain IP address !!")
                        print("    [!] Location header response : {}".format(location))
                        print(Style.RESET_ALL)
                        sock_http.close()
                        break
                    
                    print()
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " private IP address found for {}".format(host))
                    print(Fore.LIGHTGREEN_EX + "    [+]  Internal IP address : " + Fore.LIGHTGREEN_EX + location)
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " HTTP method : {}".format(method))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Redirect URL : {}".format(url))
                    sock_http.close()
                    # print("    [+] Raw request : {}".format(request))
                    break
                else:
                    print(Fore.LIGHTRED_EX)
                    print("    [-] No Internal IP address found for {}:{} with HTTP method {}".format(server_name, server_port, method))
                    print(Style.RESET_ALL)

                sock_http.close()

                    

        elif protocol == 'https':
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            for method in http_methods:

                try:
                    sock_https = socket.create_connection((server_name, server_port))
                    context = ssl.SSLContext()
                    ssock = context.wrap_socket(sock_https, server_hostname=server_name)
                    # ssock.settimeout(10)
                except:
                    print(Back.LIGHTRED_EX)
                    print("    [-] Error on connecting to host {}:{}".format(server_name, server_port))
                    print(Style.RESET_ALL)
                    sock_https.close()
                    ssock.close()
                    continue

                request = "{} {} HTTP/1.0\r\nConnection: close\r\n\r\n".format(method, url)
                ssock.sendall(request.encode())
                    
                response = ''
                recv = ssock.recv(1024).decode()
                response += recv 
                
                if response != '' and response.find("Location") > -1 and response.find("http") > -1:

                    tmp_index_1 = response.find("http")
                    tmp_index_2 = response.find(url, tmp_index_1)
                    location = response[ tmp_index_1: tmp_index_2 ]

                    if regex_compiler.match(location[8 :]) == None:
                        print("    [!] Redirectoin found with location header but no Internal IP address !!")
                        print("    [!] Location header response : {}".format(location))
                        sock_https.close()
                        ssock.close()
                        break
                    
                    print()
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " private IP address found for {}".format(host))
                    print(Fore.LIGHTGREEN_EX + "    [+]  Internal IP address : " + Fore.LIGHTGREEN_EX + location)
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " HTTP method : {}".format(method))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Redirect URL : {}".format(url))
                    # print("    [+] Raw request : {}".format(request))

                    sock_https.close()
                    ssock.close()
                    break
                else:
                    print(Fore.LIGHTRED_EX)
                    print("    [-] No Internal IP address found for {}:{} with HTTP method {}".format(server_name, server_port, method))
                    print(Style.RESET_ALL)
                
                
                sock_https.close()
                ssock.close()

        print("\n**************************************************************************************\n")

            
if __name__ == "__main__":
    enumerate_internal_IP_addresses()