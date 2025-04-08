from datetime import datetime, timezone
import random
import string
import json
import requests
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from fake_useragent import UserAgent
from colorama import Fore, init
from web3 import Web3

init(autoreset=True)
ua = UserAgent()

with open("proxies.txt", "r") as f:
    proxies_list = [line.strip() for line in f if line.strip()]
create_per_wallet = int(input("Berapa kali create pair per wallet? "))

TOKENS = {
    "Hedgemony": "0x04a9d9d4aea93f512a4c7b71993915004325ed38",
    "Hedgemony_LINK": "0x738df3f129b67f82ec1d00c0a31c50c106767a86",
    "Hedgemony_SOL": "0x1688c5364b768ae7a41e8490d632eb687faa3f73",
    "Hedgemony_UNI": "0x2f74ab02e0bc616889fa49748f0efd2dc591b9d1",
    "Hedgemony_USDC": "0xa54daa512702ceb06de4f28b7d2ae934ff3a7949",
    "Hedgemony_USDT": "0x32db151daf3934ea61b2b252cf9ba7ca25b9c7c6",
    "Hedgemony_WBTC": "0x3069974e4355cc86bde18e36e226df37c95c607c",
    "Hedgemony_WETH": "0x36393ab3d2018c2f8f08ad708690830551895857",
    "Monad": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "ShMonad": "0x3a98250f98dd388c211206983453837c8365bdc1",
    "StakedMonad": "0x07aabd925866e8353407e67c1d157836f7ad923e",
    "Tether_USD": "0x88b8e2161dedc77ef4ab7585569d2415a1c1055d",
    "USD_Coin_1": "0x5D876D73f4441D5f2438B1A3e2A51771B337F27A",
    "USD_Coin_2": "0xf817257fed379853cde0fa4f97ab987181b1e5ea",
    "Wrapped_BTC": "0xcf5a6076cfa32686c0df13abada2b40dec133f1d",
    "Wrapped_ETH": "0xb5a30b0fdc5ea94a52fdc42e3e9760cb8449fb37",
    "Wrapped_SOL": "0x369cd1e20fa7ea1f8e6dc0759709ba0bd978abe7",
    "aPriori_Monad_LST": "0xb2f82d0f38dc453d596ad40a37799446cc89274a",
    "gMON": "0xaeef2f6b429cb59c9b2d7bb2141ada993e8571c3"
}
HEDGE_TOKEN = TOKENS["Hedgemony"]
ENDPOINT = "https://alpha-api.hedgemony.xyz/strategies"

def get_wallets(file_path='pk.txt'):
    try:
        with open(file_path, 'r') as file:
            return [(Account.from_key(pk.strip()).address, pk.strip()) for pk in file if pk.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"❌ File '{file_path}' tidak ditemukan!")
        exit()

def get_proxy(proxies):
    if not proxies:
        return None
    proxy = random.choice(proxies)
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    }

def mask_address(address, show=6):
    return f"{address[:2+show]}...{address[-4:]}"

def mask_proxy(proxy):
    try:
        if '@' in proxy:
            host_port = proxy.split('@')[1]
        else:
            host_port = proxy
        host, port = host_port.split(':')
        return f"{host[:6]}...{host[-3:]}:{port}"
    except:
        return "Invalid proxy"

def generate_nonce(length=17):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_timestamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def create_sign_message(address, nonce, timestamp):
    return f"""app.hedgemony.xyz wants you to sign in with your Ethereum account:
{address}

Sign in to Hedgemony.

URI: https://app.hedgemony.xyz
Version: 1
Chain ID: 10143
Nonce: {nonce}
Issued At: {timestamp}
Resources:
- https://app.hedgemony.xyz"""

def sign_message(private_key, message):
    try:
        message_encoded = encode_defunct(text=message)
        signed_message = Account.sign_message(message_encoded, private_key)
        return signed_message.signature.hex()
    except:
        return None

def auth(address, message, signature, proxy):
    url = "https://alpha-api.hedgemony.xyz/auth"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": ua.random
    }
    payload = {
        "address": address,
        "message": message,
        "signature": "0x"+ signature
    }

    try:
        res = requests.post(url, headers=headers, json=payload, timeout=20, proxies=get_proxy([proxy]))
        if res.ok:
            token = res.json().get("accessToken")
            print(Fore.GREEN + f"✅ Login sukses: {mask_address(address)}")
            return token
        else:
            print(Fore.RED + f"❌ Gagal login: {mask_address(address)} - {res.status_code}")
            return None
    except Exception as e:
        print(Fore.RED + f"❌ Proxy/Auth error: {e}")
        return None

def generate_hedge_pair():
    input_token_name = random.choice(list(TOKENS.keys() - {"Hedgemony"}))
    pair_name = f"{input_token_name}/HEDGE"

    amount_eth = round(random.uniform(0.1, 0.5), 6) 
    amount_wei = str(Web3.to_wei(amount_eth, 'ether'))

    return {
        "chainId": 10143,
        "inputTokens": [{"address": TOKENS[input_token_name], "amount": amount_wei}],
        "marketOrders": [{"allocationPercentage": 100, "quoteToken": HEDGE_TOKEN}],
        "name": pair_name,
        "slippage": 0.5,
        "status": "NOT_STARTED",
        "singleLimitOrders": [],
        "dcas": []
    }

def create_pair_strategy(token, pair, address, proxy):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = json.dumps(pair)

    try:
        response = requests.post(ENDPOINT, headers=headers, data=payload, proxies=get_proxy([proxy]))
        res_data = response.json()
        print(Fore.CYAN + f"📈 Pair dibuat: {pair['name']} | ID: {res_data.get('id', 'N/A')} ({mask_address(address)})")
    except Exception as e:
        print(Fore.RED + f"❌ Gagal create strategy: {e}")

wallets = get_wallets()
for i, (address, pk) in enumerate(wallets):
    if i >= len(proxies_list):
        print(Fore.RED + f"❌ Tidak cukup proxy untuk wallet ke-{i+1}")
        break

    proxy = proxies_list[i]
    masked_proxy = mask_proxy(proxy)
    print(Fore.MAGENTA + f"🌐 Proxy digunakan: {masked_proxy} untuk wallet {mask_address(address)}")

    nonce = generate_nonce()
    timestamp = get_timestamp()
    message = create_sign_message(address, nonce, timestamp)
    signature = sign_message(pk, message)

    if not signature:
        print(Fore.RED + f"❌ Gagal sign message untuk {mask_address(address)}")
        continue

    token = auth(address, message, signature, proxy)
    if token:
        for _ in range(create_per_wallet):
            pair = generate_hedge_pair()
            create_pair_strategy(token, pair, address, proxy)
            delay = random.randint(12, 20)
            print(Fore.LIGHTBLACK_EX + f"⏳ Delay {delay} detik sebelum create pair berikutnya...")
            time.sleep(delay)

    print(Fore.YELLOW + "-" * 50)
