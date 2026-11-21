#!/usr/bin/env python3
"""Make deterministic, non-exploit TCP/HTTP PCAP test packets with stdlib only."""
from pathlib import Path
import socket, struct
ETH=bytes.fromhex('00005e00535100005e0053520800')

def cksum(data):
    if len(data)%2: data+=b'\x00'
    nums=struct.unpack('!%dH'%(len(data)//2),data)
    total=sum(nums)
    while total>>16: total=(total&65535)+(total>>16)
    return (~total)&65535

def packet(src,dst,sp,dp,seq,ack,flags,payload,ident):
    sb,db=socket.inet_aton(src),socket.inet_aton(dst)
    tcp=struct.pack('!HHIIHHHH',sp,dp,seq,ack,(5<<12)|flags,65535,0,0)+payload
    pseudo=sb+db+struct.pack('!BBH',0,6,len(tcp))
    tcp=tcp[:16]+struct.pack('!H',cksum(pseudo+tcp))+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),ident,0,64,6,0,sb,db)
    ip=ip[:10]+struct.pack('!H',cksum(ip))+ip[12:]
    return ETH+ip+tcp

def request(uri='/',method='GET',headers=(),body=b''):
    lines=[f'{method} {uri} HTTP/1.1','Host: qa.example.test',*headers,f'Content-Length: {len(body)}','Connection: close','','']
    return '\r\n'.join(lines).encode()+body

CASES={
 'artex-ua':(request(headers=['User-Agent: artex-verify/1.0']),b'OK',8080,{9876001}),
 'artex-header':(request(headers=['X-ARTX-KEY: test-only']),b'OK',8080,{9876004}),
 'artex-probe':(request('/zzz-nonexistent-xyz123'),b'OK',8080,{9876005}),
 'artex-console':(request(),b'<title>ARTEX</title><script src="/_next/static/test.js"></script>',8080,{9876009}),
 'cyberstrike-shell':(request(headers=['User-Agent: CyberStrikeAI-WebShell/1.0']),b'OK',8080,{9876011}),
 'cyberstrike-checkin':(request('/check_in','POST',['X-Session-Token: test-only']),b'OK',8080,{9876016}),
 'hexstrike-ua':(request(headers=['User-Agent: HexStrike-HTTP-Framework/1.0']),b'OK',8080,{9876020}),
 'hexstrike-xss':(request('/?q=hexstrikeXSSTest123'),b'OK',8080,{9876022}),
 'hexstrike-banner':(request(),b'HexStrike AI Tools API Server is operational',8888,{9876023}),
 'cairn-openapi':(request(),b'Fact-graph based collaborative exploration protocol',8080,{9876027}),
 'cairn-heartbeat':(request('/projects/demo/intents/1/heartbeat','POST'),b'OK',8080,{9876028}),
 'benign':(request('/healthz',headers=['User-Agent: curl/8.0']),b'OK',8080,set())
}

def generate(out):
    out=Path(out)
    out.mkdir(parents=True,exist_ok=True)
    for name,(req,resp,port,_) in CASES.items():
        s,d='192.0.2.25','198.51.100.35'
        cs,ss=10000,20000
        response=b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '+str(len(resp)).encode()+b'\r\nConnection: close\r\n\r\n'+resp
        specs=[(s,d,21000,port,cs,0,0x02,b''),(d,s,port,21000,ss,cs+1,0x12,b''),(s,d,21000,port,cs+1,ss+1,0x10,b''),(s,d,21000,port,cs+1,ss+1,0x18,req),(d,s,port,21000,ss+1,cs+1+len(req),0x18,response),(s,d,21000,port,cs+1+len(req),ss+1+len(response),0x10,b'')]
        cap=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for i,args in enumerate(specs):
            dat=packet(*args,101+i)
            cap+=struct.pack('<IIII',1795000000,i*1000,len(dat),len(dat))+dat
        (out/(name+'.pcap')).write_bytes(cap)

if __name__=='__main__':
    generate('/tmp/agentic-suricata-qa-fixtures')
    print('GENERATED',len(CASES),'inert PCAP fixtures')
