from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError

class UrlParser():
    @staticmethod
    def _url_check(url: str) -> bool:
        try:
            with urlopen(url=url) as response:
                status_code = response.getcode()
                if status_code != 200:
                    return False
            return True
                
        except URLError as err:
            allow_code = [401,402,403,404,405]
            if err.code in allow_code:
                return True
            return False
    
    def get_parser(self, url: str) -> tuple[bool,str,int]:
        try:
            obj = urlparse(url=url)
            scheme = obj.scheme if obj.scheme else 'https'
            hostname = obj.hostname
            if not hostname:
                c_str = f'{scheme}://{url}'
                obj = urlparse(url=c_str)
            
            host = obj.hostname if obj.hostname else hostname
            port = obj.port if obj.port else 443
            url = f'{scheme}://{host}:{port}'
            
            if not self._url_check(url=url):
                return False, None, None
            return True, host, port     
        except Exception as err:
            return False, None, None