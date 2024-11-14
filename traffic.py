import requests
import threading
import time
import random

url = "http://127.0.0.1:5000/"

def send_request():
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Request successful to {url} - Status Code: {response.status_code}")
        else:
            print(f"Request failed to {url} - Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")

def simulate_traffic(num_requests):
    threads = []
    for i in range(num_requests):
        thread = threading.Thread(target=send_request)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    print(f"Starting traffic simulation to {url}")
    num_requests = 2000000
    simulate_traffic(num_requests)
    print(f"Completed {num_requests} requests to {url}")
