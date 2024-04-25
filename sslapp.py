import ssl
import sys
import socket
import json
import argparse
from datetime import datetime
from src.url_parser import UrlParser

class SSLApp():
    def __init__(self, host:str, s_port: int) -> None:
        ctx: ssl.SSLContext = ssl.create_default_context()
        try:
            with socket.create_connection((host, s_port)) as self.sock:
                with ctx.wrap_socket(self.sock, server_hostname=host) as s:
                    self.ret = s.getpeercert()
        except Exception as err:
            sys.exit()
            
    @staticmethod
    def _expire_date(end_date: str) -> str:
        try:
            now_date = datetime.now()
            expire_date = end_date - now_date
            if expire_date.days < -1:
                return '-1 days'
            ret = f'{expire_date.days} Days.'
        except:
            ret = '0 Days'
        return ret

    def convert_dict2json(self, data: dict) -> str:
        dns_list: list[str] = []
        for i in data['subjectAltName']:
            dns_list.append(i[-1])
            
        subjectaltname_data: dict[str,list[str]] = {
            "DNS": dns_list
        }
        start_date = datetime.strptime(data['notBefore'], "%b %d %H:%M:%S %Y %Z")
        end_date = datetime.strptime(data['notAfter'], "%b %d %H:%M:%S %Y %Z")
        expire_date = self._expire_date(end_date=end_date)
        
        ret = {
            "status": {
                "code": 0,
                "msg": "SSL Certification information"
            },
            
            "result": {
                "subject": dict(i[0] for i in data['subject']),
                "issuer": dict(i[0] for i in data['issuer']),
                "notBefore": str(start_date),
                "notAfter": str(end_date),
                "expireDate": expire_date,
                "subjectAltName": subjectaltname_data
            }
        }
        return json.dumps(ret, indent=4, sort_keys=True)
        
    def run(self) -> str:
        return self.convert_dict2json(data=self.ret)
    
    def __del__(self) -> None:
        self.sock.close()
    

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="SSL 인증서 정보", description="SSL 인증서 정보 추출", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    # 입력 유효성 체크
    if len(sys.argv) == 1:
        ret = {
            "status": {
                "code": 1,
                "msg": "Input the URL"
            },
            "result": {}
        }
        print(json.dumps(ret, indent=4, sort_keys=True))
        sys.exit()
    
    parser.add_argument('url', type=str, help='검사할 URL 주소')
    parser.add_argument('-e', '--expire', action='store_true', dest='exp', help='인증서 유효일 확인')
    
    try:
        args = parser.parse_args()
        up = UrlParser().get_parser(url=args.url)
        if not up[0]:
            ret = {
                "status": {
                    "code": 1,
                    "msg": "URL is not valid"
                },
                "result": {}
            }
            print(json.dumps(ret, indent=4, sort_keys=True))
            sys.exit()
        
        sslapp: SSLApp = SSLApp(host=up[1], s_port=up[-1])
        obj: str = sslapp.run()
        if args.exp:
            ret = {
                "status": {
                    "code": 0,
                    "msg": "SSL expire date"
                },
                "result": {
                    "expireDate": json.loads(obj)['result']['expireDate']
                }
            }
            print(json.dumps(ret, indent=4, sort_keys=True))
        else:
            print(obj)
        sys.exit()
    
    except Exception as err:
        print(err)
        ret = {
            "status": {
                "code": 1,
                "msg": "ArgumentParser Error"
            },
            "result": {}
        }
        print(json.dumps(ret, indent=4, sort_keys=True))
        sys.exit(0)        
        
    
if __name__ == '__main__':
    main()