import os
import sys
import yaml
import json
from openai import OpenAI
from anthropic import Client
from ollama import Client as OllamaClient
import argparse
from datetime import datetime, date
from jinja2 import Environment, FileSystemLoader

class Config:
    OPENAI_KEY = "OPENAI_KEY"
    ANTHROPIC_KEY = "ANTHROPIC_KEY"
    HTML_OUTPUT_FILE = 'report.html'
    TEMPLATE_FILE = 'template.html'
    MODEL = 'gpt-3.5-turbo'
    CROSS_VALIDATION = False
    DEBUG = False

    @staticmethod
    def set_output_file(service_name):
        current_date = date.today().strftime("%Y-%m-%d")
        Config.HTML_OUTPUT_FILE = f"{service_name.replace(' ', '_')}_{current_date}_ThreatModelingReport.html"

class YAMLDataHandler:
    @staticmethod
    def load_and_validate_yaml_file(file_path):
        try:
            with open(file_path, 'r') as file:
                data = yaml.safe_load(file)
        except FileNotFoundError:
            return False, None, f"Error: File '{file_path}' not found."
        except yaml.YAMLError as e:
            return False, None, f"YAML syntax error in '{file_path}': {e}"
        valid, message = YAMLDataHandler.validate_yaml_data(data)
        if not valid:
            return False, None, message
        return True, data, "YAML file is valid."

    @staticmethod
    def validate_yaml_data(data):
        required_keys = {
            'Version': str,
            'Date': '%d.%m.%Y',
            'Description': {'Name', 'Type', 'Criticality'},
            'DataProcessed': {'Type', 'DataCategory', 'EncryptionAtRest'},
            'Components': {'Internal', 'External'},
            'Pipeline': {'Type', 'CODEOWNERS', 'BranchProtection', 'SignCommits', 'PinActions'},
            'Network': {'Access'},
            'dataFlow': list
        }
        for key, expected in required_keys.items():
            if key not in data:
                return False, f"Missing key: '{key}' in YAML data."
            if isinstance(expected, set) and not expected.issubset(data[key].keys()):
                return False, f"Missing keys in '{key}': {expected - data[key].keys()}"
            if isinstance(expected, type) and not isinstance(data[key], expected):
                return False, f"'{key}' should be of type {expected.__name__}."
            if key == 'Date':
                try:
                    datetime.strptime(data[key], required_keys[key])
                except ValueError:
                    return False, f"'Date' is not in the correct format (DD.MM.YYYY)."
        return True, "YAML data is valid."

class ThreatModeling:
    def __init__(self, service_description, model):
        self.service_description = service_description
        self.model = model
        
        self.openai_client = None
        self.anthropic_client = None
        self.ollama_client = None

        if self.model in ['gpt-3.5-turbo', 'gpt-4']:
            openai_key = os.getenv(Config.OPENAI_KEY)
            if openai_key:
                self.openai_client = OpenAI(api_key=openai_key)
        elif self.model == 'claude':
            anthropic_key = os.getenv(Config.ANTHROPIC_KEY)
            if anthropic_key:
                self.anthropic_client = Client(api_key=anthropic_key)
        elif self.model == 'mistral':
            # Uses environment variable OLLAMA_HOST if set (e.g., for Docker)
            self.ollama_client = OllamaClient()

    @staticmethod
    def convert_data_flow_to_json(data_flows):
        nodes = set()
        links = []
        for flow in data_flows:
            for interaction in flow['interactions']:
                nodes.add(interaction['from'])
                nodes.add(interaction['to'])
                links.append({
                    "source": interaction['from'],
                    "target": interaction['to'],
                    "type": interaction['method']
                })
        return json.dumps({"nodes": list(map(lambda x: {"id": x}, nodes)), "links": links})

    def generate_threat_modeling(self):
        if self.model in ['gpt-3.5-turbo', 'gpt-4']:
            return self.generate_threat_modeling_openai()
        elif self.model == 'claude':
            return self.generate_threat_modeling_anthropic()
        elif self.model == 'mistral':
            return self.generate_threat_modeling_ollama()
        else:
            raise ValueError(f"Unsupported model: {self.model}")

    def generate_threat_modeling_openai(self):
        if not self.openai_client:
            return "<p>OpenAI key was not provided or is incorrect. AI Threat Modeling was not performed.</p>"

        prompt = f"""Perform a thorough threat modeling analysis for the provided service, utilizing the STRIDE framework, OWASP Top 10 2021, and OWASP Top 10 CI/CD Security Risks guidelines. Return the analysis in JSON format with the following structure. Generate multiple threats.
        {{
            "threats": [
                {{
                    "title": "Threat Title",
                    "description": "Detailed threat description.",
                    "categories": ["STRIDE Category", "OWASP Top 10 2021 Category", "OWASP Top 10 CI/CD Security Risks Category"],
                    "remediation": "Recommended steps or strategies to mitigate or resolve the threat.",
                    "validator": "🟢 {self.model}"
                }}
            ]
        }}

        Service data:
        {self.service_description}
        """

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Provide a threat analysis. DO NOT output ellipses (...) in the JSON array."},
                    {"role": "user", "content": prompt}
                ]
            )
            response_text = response.choices[0].message.content.strip()
            log(f"OpenAI API Response: {response_text}")

            json_start = response_text.find("{")
            json_end = response_text.rfind("}")
            if json_start != -1 and json_end != -1:
                json_content = response_text[json_start:json_end+1]
                try:
                    threat_analysis_json = json.loads(json_content)
                    return json.dumps(threat_analysis_json)
                except json.JSONDecodeError:
                    log("Failed to parse extracted JSON content.")
            else:
                log("Failed to extract JSON content from the response.")

            return "[]"
        except Exception as e:
            log(f"Error generating threat modeling with OpenAI: {str(e)}")
            return f"<p>Error generating threat modeling: {str(e)}</p>"

    def generate_threat_modeling_anthropic(self):
        if not self.anthropic_client:
            return "<p>Anthropic key was not provided or is incorrect. AI Threat Modeling was not performed.</p>"

        prompt = f"""Perform a thorough threat modeling analysis for the provided service, utilizing the STRIDE framework, OWASP Top 10 2021, and OWASP Top 10 CI/CD Security Risks guidelines. Return the analysis in JSON format with the following structure. Generate multiple threats.
        {{
            "threats": [
                {{
                    "title": "Threat Title",
                    "description": "Detailed threat description.",
                    "categories": ["STRIDE Category", "OWASP Top 10 2021 Category", "OWASP Top 10 CI/CD Security Risks Category"],
                    "remediation": "Recommended steps or strategies to mitigate or resolve the threat.",
                    "validator": "🟢 {self.model}"
                }}
            ]
        }}

        Service data:
        {self.service_description}
        """

        try:
            response = self.anthropic_client.messages.create(
                max_tokens=2048,
                model="claude-3-haiku-20240307",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            response_text = response.content[0].text.strip()

            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start != -1 and json_end != -1:
                json_content = response_text[json_start:json_end].strip()
                try:
                    threat_analysis_json = json.loads(json_content)
                    return json.dumps(threat_analysis_json)
                except json.JSONDecodeError:
                    log("Failed to parse extracted JSON content.")
            else:
                log("Failed to extract JSON content from the response.")

            return "[]"

        except Exception as e:
            log(f"Error generating threat modeling with Anthropic: {str(e)}")
            return f"<p>Error generating threat modeling: {str(e)}</p>"
        
    def generate_threat_modeling_ollama(self):
        prompt = f"""Perform a thorough threat modeling analysis for the provided service. 
        Utilize the STRIDE framework, OWASP Top 10 2021, and OWASP Top 10 CI/CD Security Risks guidelines.
        
        You must return your response in this exact JSON structure:
        {{
            "threats": [
                {{
                    "title": "Threat Title",
                    "description": "Detailed threat description.",
                    "categories": ["STRIDE", "OWASP"],
                    "remediation": "Recommended mitigation steps.",
                    "validator": "🟢 {self.model}"
                }}
            ]
        }}

        Do not use ellipses (...) or placeholders. Output multiple realistic threats based on the data.

        Service data:
        {self.service_description}
        """

        try:
            response = self.ollama_client.generate(
                model="mistral:7b",
                prompt=prompt,
                format="json",
                options={"temperature": 0.1}, 
                stream=False,
                system="You are an expert security engineer. Identify threats and output strictly valid JSON matching the requested schema."
            )
            
            response_text = response['response'].strip()
            if not response_text:
                return "[]"

            try:
                threat_analysis_json = json.loads(response_text)
                if isinstance(threat_analysis_json, list):
                    threat_analysis_json = {"threats": threat_analysis_json}
                return json.dumps(threat_analysis_json)
            except json.JSONDecodeError as err:
                log(f"Ollama JSON format parse failed: {err}. Attempting fallback parsing...")
                
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                if json_start == -1:
                    json_start = response_text.find("[")
                    json_end = response_text.rfind("]") + 1
                    
                if json_start != -1 and json_end != -1:
                    clean_content = response_text[json_start:json_end]
                    threat_analysis_json = json.loads(clean_content)
                    if isinstance(threat_analysis_json, list):
                        threat_analysis_json = {"threats": threat_analysis_json}
                    return json.dumps(threat_analysis_json)
                raise err

        except Exception as e:
            log(f"Error generating threat modeling with Ollama: {str(e)}")
            return "[]"

    @staticmethod
    def validate_threats(threats, validation_model, client):
        validated_threats = []
        for threat in threats:
            prompt = f"""
            Please validate the following threat:
            {{
                "title": "{threat.get('title', threat.get('Title', ''))}",
                "description": "{threat.get('description', threat.get('Description', ''))}",
                "categories": {threat.get('categories', threat.get('Categories', []))},
                "remediation": "{threat.get('remediation', threat.get('Remediation', ''))}"
            }}
            Is this a valid threat? Respond with 'Yes' or 'No'.
            """
            if validation_model in ['gpt-3.5-turbo', 'gpt-4']:
                response = client.chat.completions.create(
                    model=validation_model,
                    messages=[
                        {"role": "system", "content": "You are a security expert. Validate the threat."},
                        {"role": "user", "content": prompt}
                    ]
                )
                is_valid = response.choices[0].message.content.strip().lower() == 'yes'
            elif validation_model == 'claude':
                response = client.messages.create(
                    max_tokens=5,
                    model="claude-3-haiku-20240307",
                    messages=[{"role": "user", "content": prompt}]
                )
                is_valid = 'yes' in response.content[0].text.strip().lower()
            elif validation_model == 'mistral':
                response = client.generate(
                        model="mistral:7b",
                        prompt=prompt,
                        stream=False,
                        system="You are a security expert. Validate the threat."
                )
                is_valid = 'yes' in response['response'].lower()
            else:
                raise ValueError(f"Unsupported validation model: {validation_model}")

            validator = threat.get("validator", threat.get("Validator", ""))
            if is_valid:
                threat['validator'] = f"{validator} 🟢 {validation_model}"
            else:
                threat['validator'] = f"{validator} 🔴 {validation_model}"

            validated_threats.append(threat)
        return validated_threats

    @staticmethod
    def remove_duplicate_threats(threats):
        unique_threats = []
        seen_titles = set()
        for threat in threats:
            title = threat.get('title', threat.get('Title', ''))
            if title not in seen_titles:
                unique_threats.append(threat)
                seen_titles.add(title)
        return unique_threats

class HTMLReportRenderer:
    def __init__(self, service_info, data_flow_json, threat_analysis_html):
        self.service_info = service_info
        self.data_flow_json = data_flow_json
        self.threat_analysis_html = threat_analysis_html
        self.service_name = service_info.get('Description', {}).get('Name', 'Report')
        self.current_date = date.today().strftime("%Y-%m-%d")

    def render(self):
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template(Config.TEMPLATE_FILE)
        return template.render(
            service=self.service_info,
            data_flow_json=self.data_flow_json,
            threat_analysis_html=self.threat_analysis_html,
            service_name=self.service_name,
            current_date=self.current_date
        )

class PrintManager:
    TITLE_STYLE = '\033[1;34m'
    NORMAL_STYLE = '\033[0m'
    NAME_STYLE = '\033[1;32m'
    HIGHLIGHT_STYLE = '\033[1;33m'
    FILE_STYLE = '\033[1;33m'
    ERROR_STYLE = '\033[1;31m'

    @staticmethod
    def print_usage():
        print(f"{PrintManager.TITLE_STYLE}AI-driven Threat modeling-as-a-Code (TaaC) v1.1{PrintManager.NORMAL_STYLE}")
        print(f"Created by YevhSec1\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Usage:{PrintManager.NORMAL_STYLE} python3 TaaC.py [options] <yaml_file>\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Options:{PrintManager.NORMAL_STYLE}")
        print("  -h, --help            show this help message and exit")
        print("  --model               Select the model version: gpt-3.5-turbo or gpt-4")
        print("  --cross-validation    Perform cross-validation using two LLMs")
        print("  --debug               Enable debug logging\n")

    @staticmethod
    def print_progress(file_name):
        print(f"{PrintManager.TITLE_STYLE}Processing: {file_name}{PrintManager.NORMAL_STYLE}")
        print("Generating report... Please wait.")

    @staticmethod
    def print_completion():
        print(f"\n{PrintManager.NAME_STYLE}Done! The report has been successfully generated.{PrintManager.NORMAL_STYLE}\n")

    @staticmethod
    def print_error(message):
        print(f"{PrintManager.ERROR_STYLE}Error:{PrintManager.NORMAL_STYLE} {message}")

def safe_extract_threats(parsed_json):
    """Safely extracts the list of threats regardless of casing."""
    if isinstance(parsed_json, list):
        return parsed_json
    if isinstance(parsed_json, dict):
        for key in ['threats', 'Threats', 'THREATS']:
            if key in parsed_json:
                return parsed_json[key]
    return []

def convert_json_to_html(json_data):
    try:
        parsed_data = json.loads(json_data)
        threats = safe_extract_threats(parsed_data)
    except (json.JSONDecodeError, TypeError) as e:
        log(f"Error parsing JSON data: {str(e)}")
        return '<tr><td colspan="7">Error parsing AI response format.</td></tr>'

    if not threats:
        return '<tr><td colspan="7">No threats found.</td></tr>'

    html = ''
    for threat in threats:
        title = threat.get("title", threat.get("Title", "N/A"))
        validator = threat.get("validator", threat.get("Validator", "🟢"))
        description = threat.get("description", threat.get("Description", "N/A"))
        remediation = threat.get("remediation", threat.get("Remediation", "N/A"))
        
        categories = threat.get("categories", threat.get("Categories", []))
        if isinstance(categories, list):
            cat_str = ", ".join(categories)
        else:
            cat_str = str(categories)

        html += '<tr>\n'
        html += f'<td contenteditable="true">{title}</td>\n'
        html += f'<td>{validator}</td>\n'
        html += f'<td contenteditable="true">{description}</td>\n'
        html += f'<td contenteditable="true">{cat_str}</td>\n'
        html += f'<td contenteditable="true">{remediation}</td>\n'
        html += '<td><input type="checkbox" onchange="toggleStrikeThrough(this)"></td>\n'
        html += '<td>'
        html += '<button class="table-button" onclick="saveThreat(this.parentNode.parentNode)">Save</button>'
        html += '<button class="table-button delete-button" onclick="deleteThreat(this.parentNode.parentNode)">Delete</button>'
        html += '</td>\n'
        html += '</tr>\n'
    return html

def parse_arguments():
    parser = argparse.ArgumentParser(description='Generate a threat modeling report from a YAML file.')
    parser.add_argument('yaml_file', help='Path to the YAML file containing the service information.')
    parser.add_argument('--model', choices=['gpt-3.5-turbo', 'gpt-4', 'claude', 'mistral'], default='gpt-3.5-turbo', help='Choice of LLM for generating the report.')
    parser.add_argument('--cross-validation', choices=['gpt-3.5-turbo', 'gpt-4', 'claude', 'mistral'], help='Perform cross-validation using two LLMs.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    return parser.parse_args()

def log(message):
    if Config.DEBUG:
        print(f"[DEBUG] {message}")

def main():
    args = parse_arguments()

    Config.MODEL = args.model
    Config.CROSS_VALIDATION = args.cross_validation
    Config.DEBUG = args.debug

    valid, service_info, message = YAMLDataHandler.load_and_validate_yaml_file(args.yaml_file)
    if not valid:
        PrintManager.print_error(message)
        return

    service_name = service_info.get('Description', {}).get('Name', 'Report')
    Config.set_output_file(service_name)

    PrintManager.print_progress(args.yaml_file)
    
    data_flows = service_info.get('dataFlow', [])
    data_flow_json = ThreatModeling.convert_data_flow_to_json(data_flows)
    
    threat_modeling = ThreatModeling(json.dumps(service_info, indent=2), args.model)
    threat_analysis_json = threat_modeling.generate_threat_modeling()
    log(f"Threat Analysis JSON: {threat_analysis_json}")

    if Config.CROSS_VALIDATION:
        validation_model = Config.CROSS_VALIDATION
        log(f"Performing cross-validation using {validation_model}")
        threat_modeling_validation = ThreatModeling(json.dumps(service_info, indent=2), validation_model)
        
        parsed_analysis = json.loads(threat_analysis_json)
        threats = safe_extract_threats(parsed_analysis)
        
        log(f"Threats identified by {args.model}: {len(threats)}")
        
        if threats:
            validated_threats = ThreatModeling.validate_threats(
                threats,
                validation_model,
                threat_modeling_validation.openai_client if validation_model.startswith('gpt') else  threat_modeling_validation.ollama_client if validation_model == 'mistral' else  threat_modeling_validation.anthropic_client
            )
            threat_analysis_json = json.dumps({'threats': validated_threats})
            log(f"Updated threat analysis JSON with validation results.")

    threat_analysis_html = convert_json_to_html(threat_analysis_json)
    
    renderer = HTMLReportRenderer(service_info, data_flow_json, threat_analysis_html)
    html_report = renderer.render()
    
    with open(Config.HTML_OUTPUT_FILE, 'w') as file:
        file.write(html_report)
    PrintManager.print_completion()

if __name__ == "__main__":
    main()