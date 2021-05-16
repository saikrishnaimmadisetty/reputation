from abc import ABC, abstractmethod
import json
import base64
import logging
import requests
from netaddr import IPAddress

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Common(ABC):

    def __init__(self, ip=None, domain=None, url=None):
        if ip is not None:
            self.ip = ip
        elif domain is not None:
            self.domain = domain
        elif url is not None:
            self.url = url

    def read_config(self, section, key):
        """

        :param section: For the TI feed selection
        :param key: For api key or urls
        :return: respective output
        """
        with open('configuration.json', 'r') as config_file:
            data = json.load(config_file)
            return data.get(section)[key]

    def validate_ip(self, ip):
        """

        :param ip: For validating the IP is private or public
        :return: return the respective output
        """
        try:
            ipinfo = IPAddress(ip)
            if ipinfo.version in [4, 6]:
                if ipinfo.is_private():
                    return False
                else:
                    return True
            else:
                return False
        except Exception:
            return False

    def base_64(self):
        """

        :return: It encode and decode the input and then return the value
        """
        apikey = f'{self.read_config(section="IBMXFORCE", key="apikey")}'
        password = self.read_config(section="IBMXFORCE", key="password")
        string = f'{apikey}:{password}'
        string_bytes = string.encode("ascii")
        base64_bytes = base64.b64encode(string_bytes)
        base64_string = base64_bytes.decode("ascii")
        Auth_key = f'Basic {base64_string}'
        return Auth_key

    @abstractmethod
    def ip_check(self):
        pass

    @abstractmethod
    def domain_check(self):
        pass

    @abstractmethod
    def url_check(self):
        pass


class Virustotal(Common):

    def ip_check(self):
        """

        :return: To check the reputation of IP and get required details
        """
        if self.validate_ip(self.ip):
            url = f"{self.read_config(section='virustotal', key='base_url')}{self.read_config(section='virustotal', key='ip_endpoint').replace('{ip}', self.ip)}"  # pylint: disable=line-too-long
            params = {'x-apikey': self.read_config(section='virustotal', key='apikey')}
            response = requests.get(url, headers=params)
            if response.status_code == 200:
                output = response.json()
                if output != 0:
                    logger.info(f'regional_internet_registry={output["data"]["attributes"]["regional_internet_registry"]}')  # pylint: disable=line-too-long
                    logger.info(f'as_owner={output["data"]["attributes"]["as_owner"]}')
                    logger.info(f'network={output["data"]["attributes"]["network"]}')
                    logger.info(f'country={output["data"]["attributes"]["country"]}')
                    stat_keys = output['data']['attributes']['last_analysis_results']
                    list_stat_keys = list(stat_keys.keys())
                    for i in list_stat_keys:
                        category = output['data']['attributes']['last_analysis_results'][f'{i}']['category']
                        harmless = "harmless"
                        if category == harmless:
                            continue
                        else:
                            logger.info("===========================================")
                            logger.info(f"category is {output['data']['attributes']['last_analysis_results'][f'{i}']['category']}")  # pylint: disable=line-too-long
                            logger.info(f"result is {output['data']['attributes']['last_analysis_results'][f'{i}']['result']}")  # pylint: disable=line-too-long
                            logger.info(f"method is {output['data']['attributes']['last_analysis_results'][f'{i}']['method']}")  # pylint: disable=line-too-long
                            logger.info(f"engine name is {output['data']['attributes']['last_analysis_results'][f'{i}']['engine_name']}")  # pylint: disable=line-too-long
                            logger.info("===========================================")
                else:
                    logger.info('nothing to display')
            else:
                logger.error(f'error status code={response.status_code} | reason={response.reason}')
        else:
            logger.warning(f'Provided IP {self.ip} is Invalid for Reputation check..!')


    def domain_check(self):
        """

        :return: To chech the reputation of domain and retrieve the details
        """
        url = f"{self.read_config(section='virustotal', key='base_url')}{self.read_config(section='virustotal', key='domain_endpoint').replace('{domain}', self.domain)}"  # pylint: disable=line-too-long
        params = {'x-apikey': self.read_config(section='virustotal', key='apikey')}
        response = requests.get(url, headers=params)
        if response.status_code == 200:
            output = response.json()
            if output != 0:
                logger.info(f'whois_details={output["data"]["attributes"]["whois"]}')
                list_stat_keys = list(output['data']['attributes']['last_analysis_results'].keys())
                for i in list_stat_keys:
                    category = output['data']['attributes']['last_analysis_results'][f'{i}']['category']
                    harmless = "harmless"
                    if category == harmless:
                        continue
                    else:
                        logger.info(f"engine name is {output['data']['attributes']['last_analysis_results'][f'{i}']['engine_name']}")  # pylint: disable=line-too-long
                        logger.info(f"category is {output['data']['attributes']['last_analysis_results'][f'{i}']['category']}")  # pylint: disable=line-too-long
                        logger.info(f"result is {output['data']['attributes']['last_analysis_results'][f'{i}']['result']}")  # pylint: disable=line-too-long
                        logger.info(f"method is {output['data']['attributes']['last_analysis_results'][f'{i}']['method']}")  # pylint: disable=line-too-long
            else:
                logger.info('nothing to display')
        else:
            logger.error(f'error status code={response.status_code} | reason={response.reason}')


    def url_check(self):
        """

        :return: To chech the reputation of URL and retrieve the details
        """
        url_post = self.read_config(section='virustotal', key='url_post')
        payload = {'url': self.url}
        files = []
        headers = {'x-apikey': self.read_config(section='virustotal', key='apikey')}
        response_post = requests.post(url_post, headers=headers, data=payload, files=files)
        output1 = response_post.json()
        ids = output1['data']['id'].split("-")
        url = f"{self.read_config(section='virustotal', key='base_url')}{self.read_config(section='virustotal', key='url_endpoint')}/{ids[1]}"  # pylint: disable=line-too-long
        payload_get = {}
        response = requests.get(url, headers=headers, data=payload_get)
        if response.status_code == 200:
            output = response.json()
            if output != 0:
                logger.info(f'SHA256 = {output["data"]["attributes"]["last_http_response_content_sha256"]}')
                logger.info(f'vary = {output["data"]["attributes"]["last_http_response_headers"]["vary"]}')
                logger.info(f'Keep alive = {output["data"]["attributes"]["last_http_response_headers"]["keep-alive"]}')
                logger.info(f'server = {output["data"]["attributes"]["last_http_response_headers"]["server"]}')
                logger.info(f'content-type = {output["data"]["attributes"]["last_http_response_headers"]["content-type"]}')
                logger.info(f'reputation = {output["data"]["attributes"]["reputation"]}')
                threat_names = output["data"]["attributes"]["threat_names"]
                if len(threat_names) == 0:
                    logger.info(f'No threats detected')
                else:
                    logger.info(f'threat_names = {output["data"]["attributes"]["threat_names"]}')
                list_stat_keys = list(output['data']['attributes']['last_analysis_results'].keys())
                for i in list_stat_keys:
                    category = output['data']['attributes']['last_analysis_results'][f'{i}']['category']
                    harmless = "harmless"
                    if category == harmless:
                        continue
                    else:
                        logger.info(f"=========================== engine details =============================")
                        logger.info(f"engine name is {output['data']['attributes']['last_analysis_results'][f'{i}']['engine_name']}")  # pylint: disable=line-too-long
                        logger.info(f"category is {output['data']['attributes']['last_analysis_results'][f'{i}']['category']}")  # pylint: disable=line-too-long
                        logger.info(f"result is {output['data']['attributes']['last_analysis_results'][f'{i}']['result']}")  # pylint: disable=line-too-long
                        logger.info(f"method is {output['data']['attributes']['last_analysis_results'][f'{i}']['method']}")  # pylint: disable=line-too-long
            else:
                logger.info('nothing to display')
        else:
            logger.error(f'error status code={response.status_code} | reason={response.reason}')


class APIVoid(Common):

    def ip_check(self):
        """

        :return: To chech the reputation of IP and retrieve the details
        """
        if self.validate_ip(self.ip):
            url = f"{self.read_config(section='apivoid', key='base_url')}{self.read_config(section='apivoid', key='ip_endpoint')}?key={self.read_config(section='apivoid', key='apikey')}&ip={self.ip}"  # pylint: disable=line-too-long
            response = requests.get(url)
            if response.status_code == 200:
                output = response.json()
                if len(output) != 0:
                    value = output["data"]["report"]
                    logger.info(f'ip = {value["ip"]}')
                    logger.info(f'isp = {value["information"]["isp"]}')
                    logger.info(f'country_name = {value["information"]["country_name"]}')
                    logger.info(f'city_name = {value["information"]["city_name"]}')
                    logger.info(f'risk score is {value["risk_score"]["result"]}')
                    logger.info(f'is_proxy = {value["anonymity"]["is_proxy"]}')
                    logger.info(f'is_webproxy = {value["anonymity"]["is_webproxy"]}')
                    logger.info(f'is_vpn = {value["anonymity"]["is_vpn"]}')
                    logger.info(f'is_hosting = {value["anonymity"]["is_hosting"]}')
                    logger.info(f'is_tor = {value["anonymity"]["is_tor"]}')
                    engines = list(output["data"]["report"]["blacklists"]["engines"])
                    for i in range(len(engines)):
                        detected = output["data"]["report"]["blacklists"]["engines"][f'{i}']["detected"]
                        if detected is False:
                            continue
                        else:
                            logger.info(f'reference link is {output["data"]["report"]["blacklists"]["engines"][f"{i}"]["reference"]}')  # pylint: disable=line-too-long
                else:
                    logger.info('no data found')
            else:
                logger.info(f'error = {response.status_code}| reason = {response.reason}')
        else:
            logger.info(f'Provided IP {self.ip} is Invalid for Reputataion Check...!')

    def domain_check(self):
        """

        :return: To chech the reputation of domain and retrieve the details
        """
        url = f"{self.read_config(section='apivoid', key='base_url')}{self.read_config(section='apivoid', key='domain_endpoint')}?key={self.read_config(section='apivoid', key='apikey')}&host={self.ip}"  # pylint: disable=line-too-long
        response = requests.get(url)
        if response.status_code == 200:
            output = response.json()
            if len(output) != 0:
                value = output["data"]["report"]
                logger.info(f'ip = {value["server"]["ip"]}')
                logger.info(f'isp = {value["server"]["isp"]}')
                logger.info(f'country_name = {value["server"]["country_name"]}')
                logger.info(f'city_name = {value["server"]["city_name"]}')
                logger.info(f'risk score is {value["risk_score"]["result"]}')
                logger.info(f'reverse DNS is {value["server"]["reverse_dns"]}')
                logger.info(f'url shortner is {value["category"]["is_url_shortener"]}')
                engines = list(output["data"]["report"]["blacklists"]["engines"])
                for i in range(len(engines)):
                    detected = output["data"]["report"]["blacklists"]["engines"][f'{i}']["detected"]
                    if detected is False:
                        continue
                    else:
                        logger.info(f'reference link is {output["data"]["report"]["blacklists"]["engines"][f"{i}"]["reference"]}') # pylint: disable=line-too-long
                        logger.info(f'confidence is {output["data"]["report"]["blacklists"]["engines"][f"{i}"]["confidence"]}') # pylint: disable=line-too-long

            else:
                logger.info('no data found')
        else:
            logger.info(f'error = {response.status_code}| reason = {response.reason}')

    def url_check(self):
        """

        :return: To chech the reputation of url and retrieve the details
        """
        url = f"{self.read_config(section='apivoid', key='base_url')}{self.read_config(section='apivoid', key='url_endpoint')}?key={self.read_config(section='apivoid', key='apikey')}&url={self.ip}"  # pylint: disable=line-too-long
        response = requests.get(url)
        if response.status_code == 200:
            output = response.json()
            if len(output) != 0:
                value = output["data"]["report"]
                logger.info(f'signature = {value["file_type"]["signature"]}')
                logger.info(f'extention = {value["file_type"]["extension"]}')
                logger.info(f'headers = {value["file_type"]["headers"]}')
                logger.info(f'status = {value["response_headers"]["status"]}')
                logger.info(f'result is {value["risk_score"]["result"]}')
                logger.info(f'cache status is {value["response_headers"]["cf-cache-status"]}')
                logger.info(f'x-frame is {value["response_headers"]["x-frame-options"]}')
                engines = list(output["data"]["report"]["domain_blacklist"]["engines"])
                for i in range(len(engines)):
                    detected = output["data"]["report"]["domain_blacklist"]["engines"][i]["detected"]
                    if detected is False:
                        continue
                    else:
                        logger.info(f'reference link is {output["data"]["report"]["domain_blacklist"]["engines"][i]["reference"]}')  # pylint: disable=line-too-long
                logger.info(f'====================== ns Records ========================')
                NS_Records = value["dns_records"]["ns"]["records"]
                for i in range(len(NS_Records)):
                    logger.info(f'target is {NS_Records[i]["target"]}')
                    logger.info(f'ip is {NS_Records[i]["ip"]}')
                    logger.info(f'country is {NS_Records[i]["country_name"]}')
                    logger.info(f'isp is {NS_Records[i]["isp"]}')
                logger.info(f'====================== mx Records ========================')
                MX_Records = value["dns_records"]["mx"]["records"]
                for i in range(len(MX_Records)):
                    logger.info(f'target is {MX_Records[i]["target"]}')
                    logger.info(f'ip is {MX_Records[i]["ip"]}')
                    logger.info(f'country is {MX_Records[i]["country_name"]}')
                    logger.info(f'isp is {MX_Records[i]["isp"]}')
            else:
                logger.info('no data found')
        else:
            logger.info(f'error = {response.status_code}| reason = {response.reason}')


class IBMXFORCE(Common):

    def ip_check(self):
        """

        :return: To chech the reputation of IP and retrieve the details
        """
        if self.validate_ip(self.ip):
            url = f"{self.read_config(section='IBMXFORCE', key='base_url')}{self.read_config(section='IBMXFORCE', key='ip_endpoint').replace('{ip}', self.ip)}"  # pylint: disable=line-too-long
            Headers = {'Authorization': f'{self.base_64()}'}
            response = requests.get(url, headers=Headers)
            if response.status_code == 200:
                output = response.json()
                if output != 0:
                    IP = output['ip']
                    history = output['history']
                    country = history[0]['geo']['country']
                    logger.info(f'IP is {IP}')
                    logger.info(f'Geo location is {country}')
                    for i in range(len(history)):
                        logger.info(history[i]['reasonDescription'])
                        try:
                            logger.info(history[i]['categoryDescriptions']['Anonymisation Services'])
                        except:
                            logger.info('Anonymisation Services are not available')
                        try:
                            logger.info(f"malware description is {history[i]['categoryDescriptions']['Malware']}")
                        except:
                            logger.info('Malware info is not available')
                        logger.info(f'score is {history[i]["score"]}')
                        logger.info("\n")
                else:
                    logger.info("No details are available for the provided input")
            else:
                logger.error(f'error status code={response.status_code} | reason={response.reason}')
        else:
            logger.warning(f'Provided IP {self.ip} is Invalid for Reputation check..!')

    def domain_check(self):
        """

        :return: To chech the reputation of domain/url and retrieve the details
        """
        url = f"{self.read_config(section='IBMXFORCE', key='base_url')}{self.read_config(section='IBMXFORCE', key='url_endpoint').replace('{domain}', self.ip)}"  # pylint: disable=line-too-long
        Headers = {'Authorization': f'{self.base_64()}'}
        response = requests.get(url, headers=Headers)
        if response.status_code == 200:
            output = response.json()
            url = output['url']
            score = output['score']
            created = output['created']
            cats = output['cats']
            cats_keys = list(cats.keys())
            print(f'url is {url}', f'time is {created}', f'score is {score}', sep="\n")
            confidence = output['cats'][f'{cats_keys[0]}']['confidence']
            description = output['cats'][f'{cats_keys[0]}']['description']
            ids = output['cats'][f'{cats_keys[0]}']['reasons'][0]['id']
            name = output['cats'][f'{cats_keys[0]}']['reasons'][0]['name']
            print(f'confidence is {confidence}', f'description is {description}', f'id is {ids}', f'reason is {name}',
                  sep="\n")
        else:
            print(f'Error : {response.status_code} | Reason : {response.reason}')

    def url_check(self):
        self.domain_check()


class Engine:

    def main(self):
        """

        :return: To select the respective operation as per the user
        """
        print('Welcome to Threat Intel...!')
        print('1. Virustotal', '2. API Void', '3. IBMXFORCE', sep='\n')
        choice = input('Enter choice : ')
        if choice == '1':
            print('1. IP Check', '2. Domain Check', '3. Url Check', sep='\n')
            decision = input('Enter your IOC : ')
            if decision == '1':
                vt_obj = Virustotal(ip=input('Enter IP : '))
                vt_obj.ip_check()
            elif decision == '2':
                vt_obj = Virustotal(domain=input('Enter domain : '))
                vt_obj.domain_check()
            elif decision == '3':
                vt_obj = Virustotal(url=input('Enter url : '))
                vt_obj.url_check()
        elif choice == '2':
            print('1. IP Check', '2. Domain Check', '3. Url Check', sep='\n')
            decision = input('Enter your IOC : ')
            if decision == '1':
                void_obj = APIVoid(ip=input('Enter IP : '))
                void_obj.ip_check()
            elif decision == '2':
                void_obj = APIVoid(ip=input('Enter domain : '))
                void_obj.domain_check()
            elif decision == '3':
                void_obj = APIVoid(ip=input('Enter url : '))
                void_obj.url_check()
        elif choice == '3':
            print('1. IP Check', '2. Domain Check', '3. Url Check', sep='\n')
            decision = input('Enter your IOC : ')
            if decision == '1':
                IBM_obj = IBMXFORCE(ip=input('Enter IP : '))
                IBM_obj.ip_check()
            elif decision == '2':
                IBM_obj = IBMXFORCE(ip=input('Enter domain : '))
                IBM_obj.domain_check()
            elif decision == '3':
                IBM_obj = IBMXFORCE(ip=input('Enter url : '))
                IBM_obj.url_check()
        else:
            print('Invalid Selection, Please try again')


eng = Engine()
eng.main()