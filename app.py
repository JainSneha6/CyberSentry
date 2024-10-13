from flask import Flask, request, render_template_string, url_for
from flask_sqlalchemy import SQLAlchemy
import logging
import html
import subprocess

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

get_requests = []

@app.before_request
def log_request_info():
    # Log only GET requests
    if request.method == 'GET':
        request_info = f'GET request to {request.path} with args: {request.args}'
        app.logger.info(request_info)
        get_requests.append(request_info)  # Store request info in the list
        
@app.before_request
def log_request_info_1():
    if request.method == 'GET':
        # Store the full URL of the request, including the query string
        request_info = f'{request.url}'
        app.logger.info(f'Logged request: {request_info}')
        get_requests.append(html.escape(request_info))

@app.route('/')
def home():
    app.logger.info('GET request to home')
    return 'Home Page'

@app.route('/example', methods=['GET'])
def example():
    # Assume user input is passed as a query parameter
    user_input = request.args.get('input', '')
    
    # Vulnerable command execution (Command Injection vulnerability)
    if user_input:
        try:
            # WARNING: This is insecure and should not be used in production!
            output = subprocess.check_output(user_input, shell=True, stderr=subprocess.STDOUT, text=True)
            command_result = f'<pre>{output}</pre>'
        except subprocess.CalledProcessError as e:
            command_result = f'<pre>Error: {e.output}</pre>'
        
        # Log the command execution attempt
        app.logger.info(f'Executed command: {user_input}')
        get_requests.append(f'Executed command: {user_input}')  # Store the executed command
        
        return f'''
            <h1>Command Execution Results</h1>
            <p>Your command: {user_input}</p>
            <h2>Result:</h2>
            {command_result}
        '''

    return f'''
        <h1>Query Results</h1>
        <p>Your input: {user_input}</p>
    '''

@app.route('/requests', methods=['GET'])
def display_requests():
    # Render all GET requests in a simple HTML page
    requests_html = '<h1>Logged GET Requests</h1><ul>'
    for req in get_requests:
        requests_html += f'<li>{req}</li>'
    requests_html += '</ul>'
    return render_template_string(requests_html)

if __name__ == '__main__':
    app.run(debug=True)
