import argparse
import re
import subprocess
from urllib.parse import urljoin, urlparse
import requests
from openai import OpenAI
import yaml

# Define colors for different status codes
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"

with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

class FoundEndpoint:
    def __init__(self, endpoint, response, summary, sensitive, method, body, header, analyze_content):
        self.endpoint = endpoint
        self.response = response
        self.summary = summary
        self.sensitive = sensitive
        self.method = method
        self.body = body
        self.header = header
        self.analyze_content = analyze_content

    def create_summary(self):
        if isinstance(self.response, tuple):
            first, last = self.response
            self.summary = f"Endpoint {self.endpoint} with method {self.method} redirected from {first.status_code} to {last.status_code}"
        else:
            self.summary = f"Endpoint {self.endpoint} with method {self.method} returned status {self.response.status_code}"

    def calculate_sensitivity(self):
        if self.analyze_content:
            self.sensitive = analyze_content(self.response.text).strip()
        else:
            self.sensitive = "--"

    def to_string(self):
        if isinstance(self.response, tuple):
            first, last = self.response
            return f"{COLOR_CYAN}[+]{COLOR_RESET} {first.status_code} - {self.method} - {first.url} {COLOR_CYAN}-->{COLOR_RESET} {last.url} - {self.sensitive}"
        elif self.response.status_code in [401, 403, 405]:
            return f"{COLOR_YELLOW}[*]{COLOR_RESET} {self.response.status_code} - {self.method} - {self.endpoint} - {self.sensitive}"
        elif 500 <= self.response.status_code < 600:
            return f"{COLOR_RED}[-]{COLOR_RESET} {self.response.status_code} - {self.method} - {self.endpoint} - {self.sensitive}"
        else:
            return f"{COLOR_GREEN}[+]{COLOR_RESET} {self.response.status_code} - {self.method} - {self.endpoint} - {self.sensitive}"

    def search_and_add_endpoints(self, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content):
        base_url = urlparse(self.endpoint)
        base_domain = f"{base_url.scheme}://{base_url.netloc}"

        if isinstance(self.response, tuple):
            response_content = self.response[1].text
        else: 
            response_content = self.response.text

        urls = re.findall(r'href=[\'"]?([^\'" >]+)', response_content)

        for url in urls:
            url = url.split('#')[0].split('?')[0]
            
            full_url = urljoin(self.endpoint, url)
            parsed_url = urlparse(full_url)
            
            if protocol and parsed_url.scheme != protocol:
                continue
            
            if parsed_url.netloc != base_url.netloc:
                continue

            if is_blacklisted(full_url, blacklist) or any(full_url == ep.endpoint for ep in endpoints):
                continue

            response = send_request(full_url, headers)
            handle_response(full_url, response, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content, "Recursive")


def call_ask_gpt(prompt, model):
    client = OpenAI(api_key=config["openai_key"])

    response = client.chat.completions.create(model=model,
    messages=[
        {"role": "system", "content": "You are an assistand and guide for penetration tester and security analyst specializing in web application security"},
        {"role": "user", "content": prompt }
    ])

    return response.choices[0].message.content

def get_tech(url):
    try:
        wappy_process = subprocess.Popen(
            ['wappy', '-u', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = wappy_process.communicate()  # Use communicate instead of .read()
        if wappy_process.returncode != 0:
            raise Exception(f"Error running wappy: {stderr.strip()}")
        return stdout.split("\n", 2)[2]  # Safely split and handle output
    except Exception as e:
        print(f"Failed to retrieve tech stack for {url}: {e}")
        return "Unknown Tech"

def get_extensions(endpoints):
    return "Sample Exten"

def wordlist_fuzz(url, wordlist, endpoints, headers, non_existant_response, blacklist, analyze_content, include_5xx=False, protocol=None):
    try:
        with open(wordlist, 'r') as wl:
            for line in wl:
                fuzz_url = f"{url}/{line.strip()}"

                if is_blacklisted(fuzz_url, blacklist):
                    continue

                if any(fuzz_url == ep.endpoint for ep in endpoints):
                    continue

                response = send_request(fuzz_url, headers)
                handle_response(fuzz_url, response, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content, "Normal Wordlist")
    except FileNotFoundError:
        print(f"Wordlist file {wordlist} not found.")
    except Exception as e:
        print(f"An error occurred while fuzzing with wordlist: {e}")


def gau_fuzz(url, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content):
    try:
        result = subprocess.run(['gau', url, " --fp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        gau_output = result.stdout
        gau_endpoints = list(set(endpoint.split('?')[0].split('#')[0] for endpoint in gau_output.splitlines()))

        for gau_endpoint in gau_endpoints:
            if is_blacklisted(gau_endpoint, blacklist):
                continue

            if any(gau_endpoint == ep.endpoint for ep in endpoints):
                continue

            parsed_url = urlparse(gau_endpoint)

            if protocol and parsed_url.scheme != protocol:
                continue
            
            response = send_request(gau_endpoint, headers)
            handle_response(gau_endpoint, response, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content, "Gau")

    except Exception as e:
        print(f"An error occurred while running gau: {e}")

def openai_fuzz(endpoints, naming_convention, tech, headers, non_existant_response, blacklist, include_5xx, protocol, size, analyze_content):
    prompt = createPrompt(endpoints, naming_convention, tech, size)
    urls_string = call_ask_gpt(prompt, "gpt-4o")   
    generated_wordlist = urls_string.strip().split("\n")[1:-1]

    for endpoint in generated_wordlist:
        try:
            fuzz_url = f"{endpoint}"
            
            response = send_request(fuzz_url, headers)
            
            handle_response(
                    fuzz_url, 
                    response, 
                    endpoints, 
                    headers, 
                    non_existant_response, 
                    blacklist, 
                    include_5xx, 
                    protocol, 
                    analyze_content,
                    source="OpenAI Fuzzing"
                )
        except Exception as e:
            print(str(e))

def get_naming_convention(endpoints):
    prompt = "Extract the naming convention used for the following API endpoints. Look for patterns in naming, resource naming, or structures and give your results briefly. Here are the endpoints:\n\n"

    for i, endpoint in enumerate(endpoints):
        prompt += f"{i+1}. {endpoint.endpoint}\n"
    
    prompt += "\nWhat naming conventions can be inferred from these endpoints? dont give me an analyze one by one. give me like 2-3 sentences describing a common \
                pattern or dotation or whatever used by these endpoints, just point it. If there is none to conclude and there is no common patterns just aswer with 'None'."

    naming_convention = call_ask_gpt(prompt, "gpt-4o")

    return naming_convention

def createPrompt(requests, naming_convention, tech, size):
    prompt = f"I have a list of found API endpoints from a web application, along with some information about the naming convention and the tech stack.\
          Based on this data, I need your help to generate a list of {size} potential additional URL paths that could be useful for fuzzing. \
            Here’s the relevant information:\n\n"

    prompt += "### Found Endpoints:\n"
    for i, request in enumerate(requests):
        prompt += f"{i+1}. {request.endpoint} ({request.method})\n"
    
    prompt += f"\n### Detected Naming Convention:\n{naming_convention}\n"

    prompt += f"\n### Detected Tech Stack:\n{tech}\n"

    prompt += f"\nGiven the above endpoints, naming convention, and technology stack, generate a list of additional potential URL paths for \
        API endpoints that might exist, give the whole url. These URLs should follow the pattern of the discovered \
        endpoints and be relevant to the tech stack, you can suggest endpoints related to the technology, \
        you should also suggest some endpoints using the domain name or a part of it, you know that some companies use custom endpoints using their name\
        or domain name like 'companyname.logs', dont be limited to this example and try to suggest others\
            The wordlist will be used for fuzzing purposes, answer with only the wordlist, and make sure its a {size} lines long wordlist, means with {size} urls.\
                dont numerate them or anything, make sure its just and only urls, each url in its own line, with nothing else"

    return prompt

def send_request(url, headers):
    retries = 2
    attempt = 0
    while attempt <= retries:
        try:
            response = requests.get(url, headers=headers, allow_redirects=True)
            if response.history:
                first_response = response.history[0]
                last_response = response
                return first_response, last_response
            else:
                return response
        except requests.RequestException as e:
            attempt += 1
            if attempt > retries:
                return None

def get_non_existant_response(url, headers):
    url += "/sdgssdgsFS541fwewefwef1212"
    response = send_request(url, headers)
    return response

def verify_Response(response, non_existant_response):
    if response is None or non_existant_response is None:
        return False
    if non_existant_response.status_code == 200:
        if response.content == non_existant_response.content:
            return False
        elif 200 <= response.status_code < 300:
            return True
        return False
    else:
        if response and 200 <= response.status_code < 300:
            return True
        return False

def is_blacklisted(endpoint, blacklist):
    return any(endpoint.endswith(f".{ext.strip()}") for ext in blacklist)

def analyze_content(response):
    prompt = "This is the content of a web page, I want you to read it and tell me if it has any sensitive information of something I should take \
                a look at as a pentester, and you response should be one of these (Low, Medium, High, Critical), as the sevirity of the content, if \
                there is nothing interesting about it say Low...., make sure to respond with only one word and not give any explanation :\n\n" + response
    return call_ask_gpt(prompt,"gpt-4o-mini")



def handle_response(fuzz_url, response, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content, source):
    if response is None:
        print(f"Error handling response for {fuzz_url}")
        return
    
    if isinstance(response, tuple):
        last = response[1]
    else:
        last = response

    if last.status_code in [401, 403, 405]:
        found = FoundEndpoint(fuzz_url, response, None, None, "GET", None, headers, analyze_content)
        found.create_summary()
        found.calculate_sensitivity()
        endpoints.append(found)
        print(found.to_string() + f" - {source}")

    elif 200 <= last.status_code < 300:
        if verify_Response(last, non_existant_response):
            found = FoundEndpoint(fuzz_url, response, None, None, "GET", None, headers, analyze_content)
            found.create_summary()
            found.calculate_sensitivity()
            endpoints.append(found)
            print(found.to_string() + f" - {source}")
            found.search_and_add_endpoints(endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content)

    elif include_5xx and last.status_code >= 500:
        found = FoundEndpoint(fuzz_url, response, None, None, "GET", None, headers, analyze_content)
        found.create_summary()
        found.calculate_sensitivity()
        endpoints.append(found)
        print(found.to_string() + f" - {source}")

def main(url, headers, blacklist, include_5xx, protocol, size, analyze_content):
    endpoints = []

    non_existant_response = get_non_existant_response(url, headers)

    wordlist_fuzz(url, config["wordlist"], endpoints, headers, non_existant_response, blacklist, analyze_content, include_5xx, protocol)
    gau_fuzz(url, endpoints, headers, non_existant_response, blacklist, include_5xx, protocol, analyze_content)

    tech = get_tech(url)
    naming_convention = get_naming_convention(endpoints)
    openai_fuzz(endpoints, naming_convention, tech, headers, non_existant_response, blacklist, include_5xx, protocol, size, analyze_content)
    print(f"{COLOR_GREEN}Naming conventions noticed{COLOR_RESET} : {naming_convention}")
    print(f"{COLOR_GREEN}Technology stack detected{COLOR_RESET} : {tech}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Smart Directory Fuzzing Tool')
    parser.add_argument('url', type=str, help='The target URL for fuzzing')
    parser.add_argument('size', type=str, help='The Size (in Lines) of the Wordlist Generated by Openai')
    parser.add_argument('--headers', type=str, nargs='*', default=[], help='Custom headers to include in requests, formatted as key:value')
    parser.add_argument('--blacklist', type=str, default='', help='Comma-separated list of file extensions to blacklist (e.g., ttf,woff,svg,png)')
    parser.add_argument('--include_5xx', action='store_true', help='Include and print 5xx server errors')
    parser.add_argument('--https', action='store_true', help='Only follow HTTPS links')
    parser.add_argument('--http', action='store_true', help='Only follow HTTP links')
    parser.add_argument('--analyze_content', action='store_true', help='Analyze if the response contains sensitive information, using ChatGPT')

    args = parser.parse_args()

    url = args.url
    size =  args.size

    headers = {h.split(':')[0]: h.split(':')[1] for h in args.headers}
    
    arg_blacklist = args.blacklist.split(',') if args.blacklist else []
    default_blacklist = config.get("default_blacklist", [])
    blacklist = list(set(default_blacklist + arg_blacklist))

    protocol = None
    if args.https:
        protocol = "https"
    elif args.http:
        protocol = "http"

    main(url, headers, blacklist, args.include_5xx, protocol, size, args.analyze_content)
