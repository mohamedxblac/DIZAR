from flask import Flask, render_template, request
import pandas as pd
import requests
import time
from netmiko import ConnectHandler

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/index3')
def index3():
    return render_template('index3.html')

@app.route('/index4')
def index4():
    return render_template('index4.html')

@app.route('/index5')
def index5():
    return render_template('index5.html')

@app.route('/new_page')
def new_page():
    return render_template('new_page.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    while True:   
        if 'file' not in request.files:
            return 'No file part'

        file = request.files['file']
        if file.filename == '':
            return 'No selected file'

        file_path = 'uploaded_file.csv'
        file.save(file_path)

        domain_CSV = pd.read_csv(file_path)
        Urls = domain_CSV['Domain'].tolist()

        API_key = '1d2b4c964d358a7759af713a95a6572ffda61d5c64afa4649fb582232e1ed628'
        url = 'https://www.virustotal.com/vtapi/v2/url/report'

        for i in Urls:
            parameters = {'apikey': API_key, 'resource': i}

            response = requests.get(url=url, params=parameters)
            json_response = response.json()

            if json_response['response_code'] <= 0:
                with open('notMalicious.txt', 'a') as notfound:
                    notfound.write(i + "\tNOT found Malicious Domain\n")
            elif json_response['response_code'] >= 1:
                if json_response['positives'] <= 0:
                    with open('virustotalCleanResult.txt', 'a') as clean:
                        clean.write(i + "\t NOT Found malicious Domain\n")
                else:
                    with open('virustotalMaliciousResult.txt', 'a') as malicious:
                        malicious.write(i + "\t Malicious\t this Domains Detectd by " + str(
                            json_response['positives']) + " Solutions\n")

            time.sleep(15)

        return '', 204

@app.route('/upload_link', methods=['POST'])
def upload_link():
    if 'url' not in request.form:
        return 'No URL provided'

    url = request.form['url']

    if not url:
        return 'No URL provided'

    API_key = '1d2b4c964d358a7759af713a95a6572ffda61d5c64afa4649fb582232e1ed628'
    url_vt = 'https://www.virustotal.com/vtapi/v2/url/report'

    parameters = {'apikey': API_key, 'resource': url}
    response = requests.get(url=url_vt, params=parameters)

    if response.ok:
        json_response = response.json()
        if json_response['response_code'] <= 0:
            result = url + "\tNOT found Malicious Domain\n"
        elif json_response['response_code'] >= 1:
            if json_response['positives'] <= 0:
                result = url + "\t NOT Found malicious Domain\n"
            else:
                result = url + "\t Malicious\t this Domains Detectd by " + str(
                    json_response['positives']) + " Solutions\n"

        with open('link_scan_result.txt', 'a') as result_file:
            result_file.write(result)

        return '', 204

@app.route('/connect_ssh', methods=['POST'])
def connect_ssh():
    if request.method == 'POST':
        device_ip = request.form['device_ip']
        username = request.form['username']
        password = request.form['password']

        device = {
            'device_type': 'cisco_ios',
            'ip': device_ip,
            'username': username,
            'password': password,
        }

        try:
            connection = ConnectHandler(**device)
            output = connection.send_command('show ip interface brief')
            connection.disconnect()
            return f"<pre>{output}</pre>"
        except Exception as e:
            return str(e)

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')
