import requests
import threading
import time
import random

url = "http://127.0.0.1:5000/"
num_requests = 20000  # Total number of requests to simulate
burst_size = 20       # Number of requests in a burst
burst_interval = 1    # Seconds to wait between bursts

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
    requests_sent = 0
    while requests_sent < num_requests:
        threads = []
        # Send a burst of requests
        for i in range(burst_size):
            if requests_sent >= num_requests:
                break
            thread = threading.Thread(target=send_request)
            threads.append(thread)
            thread.start()
            requests_sent += 1
        
        # Wait for the burst to finish
        for thread in threads:
            thread.join()
        
        # Wait before sending the next burst
        time.sleep(burst_interval + random.uniform(0, 1))  # Randomize delay slightly

if __name__ == "__main__":
    print(f"Starting traffic simulation to {url}")
    simulate_traffic(num_requests)
    print(f"Completed {num_requests} requests to {url}")
