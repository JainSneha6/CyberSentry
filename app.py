from flask import Flask, request, render_template, redirect, url_for, render_template_string
import logging
import html
import subprocess
import requests
from lxml import etree  # Make sure you have lxml installed

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

get_requests = []

@app.before_request
def log_request_info():
    if request.method == 'GET':
        request_info = f'GET request to {request.path} with args: {request.args}'
        app.logger.info(request_info)
        get_requests.append(request_info)

@app.before_request
def log_request_info_1():
    if request.method == 'GET':
        request_info = f'GET request to {request.url}'
        app.logger.info(f'Logged request: {request_info}')
        get_requests.append(html.escape(request_info))

@app.route('/')
def home():
    app.logger.info('GET request to home')
    return render_template('home.html')

@app.route('/sql-injection', methods=['GET'])
def sql_injection():
    return render_template('sql_injection.html')

@app.route('/sql_injection_vul', methods=['GET','POST'])
def sql_injection_vul():
    return render_template('sql_injection_vul.html')

@app.route('/xss', methods=['GET'])
def xss():
    return render_template('xss.html')

@app.route('/xss_vul', methods=['GET', 'POST'])
def xss_vul():
    user_input = request.args.get('input', '')
    return render_template('xss_vul.html', user_input=user_input)

@app.route('/com_inj', methods=['GET'])
def com_inj():
    return render_template('com_inj.html')

@app.route('/com_inj_vul', methods=['GET', 'POST'])
def com_inj_vul():
    command_result = None
    user_input = ''
    user_input = request.args.get('input', '')
    if user_input:
        try:
            output = subprocess.check_output(user_input, shell=True, stderr=subprocess.STDOUT, text=True)
            command_result = output
        except subprocess.CalledProcessError as e:
            command_result = f'Error: {e.output}'
            
            # Log the command execution attempt
        app.logger.info(f'Executed command: {user_input}')
        get_requests.append(f'Executed command: {user_input}')

    return render_template('com_inj_vul.html', user_input=user_input, command_result=command_result)

@app.route('/idor', methods=['GET'])
def idor():
    return render_template('idor.html')

@app.route('/idor_vul', methods=['GET'])
def idor_vul():
    return render_template('idor_vul.html')

@app.route('/file_inclusion', methods=['GET'])
def file_inclusion():
    return render_template('file_inclusion.html')

@app.route('/file_inclusion_vul', methods=['GET'])
def file_inclusion_vul():
    return render_template('file_inclusion_vul.html')

@app.route('/dir_trav', methods=['GET'])
def dir_trav():
    return render_template('dir_trav.html')

@app.route('/dir_trav_vul', methods=['GET'])
def dir_trav_vul():
    pattern = request.args.get('pattern', '')
    return render_template('dir_trav_vul.html',pattern=pattern)

@app.route('/redirect', methods=['GET', 'POST'])
def open_redirect():
    return render_template('redirect.html')

@app.route('/open_redirect_vul', methods=['GET'])
def open_redirect_vul():
    redirect_url = ''
    redirect_url = request.form.get('url', '')
        
    if redirect_url:
        app.logger.info(f'Redirecting to: {redirect_url}')
        return redirect(redirect_url)
    return render_template('open_redirect_vul.html', redirect_url=redirect_url)

@app.route('/requests', methods=['GET'])
def display_requests():
    # Render all GET requests in a simple HTML page
    requests_html = '<h1>Logged GET Requests</h1><ul>'
    for req in get_requests:
        requests_html += f'<li>{req}</li>'
    requests_html += '</ul>'
    return render_template_string(requests_html)

# Sensitive data page that should not be accessible
@app.route('/admin', methods=['GET'])
def admin():
    # Simulate sensitive data like usernames, emails, and passwords
    sensitive_data = '''
    <h1>Admin Panel</h1>
    <p><strong>Username:</strong> admin</p>
    <p><strong>Password:</strong> admin1234</p>
    <p><strong>User 1:</strong> user1@example.com, Password: password1</p>
    <p><strong>User 2:</strong> user2@example.com, Password: password2</p>
    <p><strong>User 3:</strong> user3@example.com, Password: password3</p>
    '''
    return render_template_string(sensitive_data)

@app.route('/ssrf', methods=['GET'])
def ssrf():
    return render_template('ssrf.html')

@app.route('/ssrf_vul', methods=['GET', 'POST'])
def ssrf_vul():
    url_to_fetch = request.args.get('url', '')
    fetched_data = None
    error = None

    if url_to_fetch:
        try:
            # Make a request to the user-provided URL
            response = requests.get(url_to_fetch, timeout=5)
            fetched_data = response.text
            app.logger.info(f"Fetched data from {url_to_fetch}")
        except requests.exceptions.RequestException as e:
            error = f"Error: {str(e)}"
            app.logger.error(f"SSRF attempt failed: {str(e)}")

    return render_template('ssrf_vul.html', url_to_fetch=url_to_fetch, fetched_data=fetched_data, error=error)



@app.route('/xxe_vul', methods=['GET', 'POST'])
def xxe_vul():
    fetched_data = None
    error = None

    if request.method == 'POST':
        # Simulate attacker sending a crafted XML document for Windows
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<foo>XXE Test: &xxe;</foo>
        '''
        try:
            # Parse the XML data (simulate the processing)
            parser = etree.XMLParser(load_dtd=True, resolve_entities=True)  # Enable DTD loading and entity resolution
            xml_data = etree.fromstring(xxe_payload.encode('utf-8'), parser)
            fetched_data = xml_data.text  # Extract text content
            app.logger.info(f"Fetched data: {fetched_data}")
        except Exception as e:
            error = f"Error: {str(e)}"
            app.logger.error(f"XXE attempt failed: {str(e)}")

    return render_template('xxe_vul.html', fetched_data=fetched_data, error=error)




if __name__ == '__main__':
    app.run(debug=True)
