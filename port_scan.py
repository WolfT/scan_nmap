import  nmap

def scan_port(ip,port):
    nm = nmap.PortScanner()
    nm.scan(ip,port)
    for host in nm.all_hosts():
        print('-------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('state : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('-------------------------------------------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()

            for port in lport:
                print('port: %s\tstate : %s' %(port,nm[host][proto][port]['state']))

if __name__ == '__main__':
    ip = str(input("请输入扫描的ip地址： "))
    port = str(input("请输入扫描的端口: "))
    scan_port(ip,port)
