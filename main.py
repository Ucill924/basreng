from datetime import datetime
import random
import string
import json
import re
import requests
import time
from datetime import datetime, timezone
from eth_account import Account
from eth_account.messages import encode_defunct
from fake_useragent import UserAgent
from colorama import Fore, init
import base64
from web3 import Web3


with open("config.json", "r") as f:
    config = json.load(f)
swap_count = config["jumlah_swap"]
MIN_AMOUNT = config.get("min_amount")
MAX_AMOUNT = config.get("max_amount")
rpc = config["rpc"]
chain_id = config["chainId"]
w3 = Web3(Web3.HTTPProvider(rpc))
init(autoreset=True)
ua = UserAgent()

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

SPENDER = "0x0000000000001fF3684f28c67538d4D072C22734"


def approve_token(w3, private_key, token_address, chain_id, spender):
    try:
        token_address = Web3.to_checksum_address(token_address)
        account = w3.eth.account.from_key(private_key).address
        account = Web3.to_checksum_address(account)
        spender = Web3.to_checksum_address(SPENDER)

        abi = [
            {
                "constant": False,
                "inputs": [
                    {"name": "_spender", "type": "address"},
                    {"name": "_value", "type": "uint256"}
                ],
                "name": "approve",
                "outputs": [{"name": "", "type": "bool"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            }
        ]

        contract = w3.eth.contract(address=token_address, abi=abi)
        decimals = contract.functions.decimals().call()
        amount = int(1000 * (10 ** decimals))

        nonce = w3.eth.get_transaction_count(account)
        tx = contract.functions.approve(spender, amount).build_transaction({
            'from': account,
            'nonce': nonce,
            "gasPrice": w3.to_wei(60, 'gwei'),
            'gas': 200000,
            'chainId': chain_id
        })
        signed_tx = w3.eth.account.sign_transaction(
            tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(
            Fore.GREEN + f"✅ Approve 10000 {token_address[-6:]} sukses | TX: {w3.to_hex(tx_hash)}")
        time.sleep(2)
        return w3.to_hex(tx_hash)

    except Exception as e:
        print(Fore.RED + f"❌ Gagal approve {token_address[-6:]}: {e}")
        return None


def load_proxies(file_path='proxies.txt'):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        return None


def get_proxy(proxies):
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    } if proxies and (proxy := random.choice(proxies)) else None


def mask_address(address, show=6):
    return f"{address[:2+show]}...{address[-4:]}"


def get_wallets_from_pk(file_path):
    try:
        with open(file_path, 'r') as file:
            return [(Account.from_key(pk).address, pk) for pk in file if pk.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"❌ File '{file_path}' tidak ditemukan!")
        exit()


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


def decode_jwt(jwt_token):
    try:
        payload_part = jwt_token.split(".")[1]
        payload_part += '=' * (-len(payload_part) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_part)
        payload = json.loads(decoded_bytes)
        return payload
    except Exception as e:
        print(Fore.RED + f"❌ Failed to decode JWT: {e}")
        return None


def sign_message(private_key, message):
    try:
        message_encoded = encode_defunct(text=message)
        signed_message = Account.sign_message(message_encoded, private_key)
        signature = signed_message.signature.hex()
        if not signature.startswith("0x"):
            signature = "0x" + signature
        if len(signature) != 132:
            return None
        return signature
    except Exception as e:
        return None


def auth(address, message, signature, proxy=None):
    url = "https://alpha-api.hedgemony.xyz/auth"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "user-agent": ua.random,
        "referer": "https://app.hedgemony.xyz/",
        "origin": "https://app.hedgemony.xyz",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    }
    payload = {
        "address": address,
        "message": message,
        "signature": signature
    }

    while True:
        try:
            res = requests.post(url, headers=headers,
                                json=payload, proxies=proxy, timeout=20)
            if res.status_code == 502:
                print(Fore.YELLOW +
                      "⚠️ Server 502 Bad Gateway. Coba lagi dalam 60 detik...")
                time.sleep(60)
                continue
            elif res.ok:
                token = res.json().get("accessToken")
                print(Fore.GREEN + f"✅ Login sukses: {mask_address(address)}")
                return token
            else:
                print(
                    Fore.RED + f"❌ Gagal auth: {mask_address(address)} - {res.status_code}")
                print(res.text)
                return None
        except Exception as e:
            print(Fore.RED + f"❌ Auth error: {e}")
            return None


def get_price(token, address, proxy=None, output_token_address=None):
    if not output_token_address:
        token_names = list(TOKENS.keys())
        token_names.remove("Monad")
        output_token_name = random.choice(token_names)
        output_token_address = TOKENS[output_token_name]

    amount_eth = round(random.uniform(MIN_AMOUNT, MAX_AMOUNT), 6)
    amount_wei = str(Web3.to_wei(amount_eth, 'ether'))
    print(Fore.BLUE + f"🔢 Random amount: {amount_eth} MONAD")

    url = "https://alpha-api.hedgemony.xyz/swap"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
        "user-agent": ua.random,
        "referer": "https://app.hedgemony.xyz/",
        "origin": "https://app.hedgemony.xyz",
    }

    payload = {
        "chainId": chain_id,
        "inputTokens": [
            {
                "address": TOKENS["Monad"],
                "amount": amount_wei
            }
        ],
        "outputTokens": [
            {
                "address": output_token_address,
                "percent": 100
            }
        ],
        "recipient": address,
        "slippage": 5
    }

    retry_count = 0
    while True:
        try:
            res = requests.post(url, headers=headers,
                                json=payload, proxies=proxy, timeout=120)
            if res.ok:
                data = res.json()
                print(Fore.GREEN + "✅ Ambil harga berhasil diambil!")
                multicall = data.get("multicallTx", {})
                to = multicall.get("to")
                value = multicall.get("value")
                raw_data = multicall.get("data")
                if to and value and raw_data:
                    return {
                        "to": to,
                        "value": value,
                        "data": raw_data,
                        "token_address": output_token_address
                    }
                else:
                    print(Fore.YELLOW + "⚠️ multicallTx tidak lengkap.")
                    return None
            elif res.status_code == 400:
                retry_count += 1
                print(Fore.RED + f"❌ Swap gagal! Status: 400\n{res.text}")
                if retry_count >= 20:
                    print(
                        Fore.RED + "🚨 Gagal swap setelah 20 percobaan, silakan swap manual.")
                    return None
                print(Fore.YELLOW + "🔁 Coba lagi dalam 3 detik...")
                time.sleep(3)
                continue
            elif res.status_code == 502:
                print(Fore.YELLOW +
                      "⚠️ Server 502 Bad Gateway. Coba lagi dalam 60 detik...")
                time.sleep(60)
                continue
            else:
                print(
                    Fore.RED + f"❌ Swap gagal! Status: {res.status_code}\n{res.text}")
                return None
        except Exception as e:
            print(Fore.RED + f"❌ Error saat mendapatkan harga: {e}")
            print(Fore.YELLOW + "🔁 Coba lagi dalam 5 detik...")
            time.sleep(5)


def get_price_back(token, address, input_token_address, amount, proxy=None):
    adjusted_amount = amount * 0.9  # Kurangi 10%
    amount_wei = str(Web3.to_wei(adjusted_amount, 'wei'))
    print(Fore.BLUE +
          f"🔁 Kembali swap {adjusted_amount:.6f} token (90% dari {amount}) ke MONAD")

    url = "https://alpha-api.hedgemony.xyz/swap"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
        "user-agent": ua.random,
        "referer": "https://app.hedgemony.xyz/",
        "origin": "https://app.hedgemony.xyz",
    }

    payload = {
        "chainId": chain_id,
        "inputTokens": [
            {
                "address": input_token_address,
                "amount": amount_wei
            }
        ],
        "outputTokens": [
            {
                "address": TOKENS["Monad"],
                "percent": 100
            }
        ],
        "recipient": address,
        "slippage": 5
    }

    error_400_count = 0
    error_500_count = 0
    while True:
        try:
            res = requests.post(url, headers=headers,
                                json=payload, proxies=proxy, timeout=120)
            if res.ok:
                data = res.json()
                print(Fore.GREEN + "✅ Ambil harga balik berhasil diambil!")
                multicall = data.get("multicallTx", {})
                to = multicall.get("to")
                value = multicall.get("value")
                raw_data = multicall.get("data")
                if to and value and raw_data:
                    return {
                        "to": to,
                        "value": value,
                        "data": raw_data,
                        "token_address": TOKENS["Monad"]
                    }
                else:
                    print(Fore.YELLOW + "⚠️ multicallTx tidak lengkap (swap back).")
                    return None
            else:
                print(
                    Fore.RED + f"❌ Swap balik gagal! Status: {res.status_code}")
                time.sleep(10)
                print(Fore.RED + res.text)
                if res.status_code == 400:
                    error_400_count += 1
                    if error_400_count >= 5:
                        print(
                            Fore.RED + "🚨 Gagal swap balik setelah 20 percobaan (error 400). Server bermasalah, silakan swap manual.")
                        return None
                    print(Fore.YELLOW + "🔁 Error 400, coba lagi dalam 5 detik...")
                    time.sleep(5)
                    continue
                elif res.status_code == 500:
                    error_500_count += 1
                    if error_500_count >= 5:
                        print(
                            Fore.RED + "🚨 Gagal swap balik setelah 20 percobaan (error 500). Server bermasalah, silakan swap manual.")
                        return None
                    print(Fore.YELLOW + "🔁 Error 500, coba lagi dalam 10 detik...")
                    time.sleep(10)
                    continue
                else:
                    continue

        except Exception as e:
            print(Fore.RED + f"❌ Error saat swap balik: {e}")
            print(Fore.YELLOW + "🔁 Coba lagi dalam 5 detik...")
            time.sleep(5)


def Swap_via_router(w3, private_key, to, value, data, chain_id):
    try:
        account = Account.from_key(private_key)
        from_address = account.address
        nonce = w3.eth.get_transaction_count(from_address)
        priority_fee = w3.to_wei(52, 'gwei')
        max_fee = w3.to_wei(60, 'gwei')

        tx = {
            "type": 2,
            "to": Web3.to_checksum_address(to),
            "from": Web3.to_checksum_address(from_address),
            "value": int(value),
            "data": data,
            "gas": 600000,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority_fee,
            "nonce": nonce,
            "chainId": chain_id,
        }

        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(Fore.GREEN + f"✅ TX sent! Hash: {tx_hash.hex()}")
        print(Fore.CYAN + "⏳ Waiting for receipt...")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

        if receipt.status == 1:
            print(Fore.GREEN + f"🎉 TX Success")
        else:
            print(Fore.RED + f"❌ TX Failed! Block: {receipt.blockNumber}")

        return tx_hash.hex()

    except Exception as e:
        print(Fore.RED + f"❌ TX Error: {e}")
        return None


def check_token_balance(w3, wallet_address, token_address):
    try:
        token_address = Web3.to_checksum_address(token_address)
        wallet_address = Web3.to_checksum_address(wallet_address)

        abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "symbol",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function"
            }
        ]

        contract = w3.eth.contract(address=token_address, abi=abi)
        balance = contract.functions.balanceOf(wallet_address).call()

        try:
            decimals = contract.functions.decimals().call()
        except Exception:
            decimals = 18
        try:
            symbol = contract.functions.symbol().call()
        except Exception:
            symbol = "UNKNOWN"

        display_balance = balance / (10 ** decimals)
        print(
            Fore.CYAN + f"💰 [{wallet_address[-6:]}] Saldo {symbol}: {display_balance:.6f}")
        return display_balance, decimals

    except Exception as e:
        print(Fore.RED + f"❌ Gagal cek saldo token {token_address}: {e}")
        return None, 18


def report_trade_history(token, tx_hash, account, input_token_address, input_amount, output_token_address, output_amount, chain_id, proxy=None):
    url = "https://alpha-api.hedgemony.xyz/trade-history"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
        "user-agent": ua.random,
        "referer": "https://app.hedgemony.xyz/",
        "origin": "https://app.hedgemony.xyz"
    }

    payload = {
        "txHash": "0x" + tx_hash,
        "account": account,
        "chainId": chain_id,
        "date": datetime.utcnow().isoformat() + "Z",
        "tradeSource": "EOA",
        "sellTokens": [
            {
                "address": input_token_address,
                "amount": str(Web3.to_wei(input_amount, 'wei'))
            }
        ],
        "buyTokens": [
            {
                "address": output_token_address,
                "amount": str(output_amount)
            }
        ]
    }
    try:
        res = requests.post(url, headers=headers,
                            json=payload, proxies=proxy, timeout=60)
        if res.ok:
            print(Fore.GREEN + "📤 Point sukses!")
            print()
        else:
            print(
                Fore.RED + f"❌ Gagal report trade history! Status: {res.status_code}")
            print(Fore.YELLOW + res.text)
    except Exception as e:
        print(Fore.RED + f"❌ Error saat report trade history: {e}")


def handle_back_swap_report(tx_hash_back, output_token_address, address, token, proxy):
    check_url = f"https://api-fastify.blockvision.org/tx?hash=0x{tx_hash_back}"
    check_headers = {
        "accept": "application/json",
        "referer": "https://testnet.monadexplorer.com/"
    }

    in_amount = 0
    out_amount = 0

    try:
        check_response = requests.get(check_url, headers=check_headers)
        if check_response.status_code == 200:
            tx_data = check_response.json()
            status = tx_data.get("message", "")
            if status.lower() == "ok":
                tx_actions = tx_data.get("result", {}).get("txActions", [])
                swap_actions = [a for a in tx_actions if a.get("type") == "swap"]

                if swap_actions:
                    last_swap = swap_actions[-1]
                    in_amount = int(last_swap.get("inAmount", 0))
                    out_amount = int(last_swap.get("outAmount", 0))
                else:
                    print(Fore.YELLOW + "⚠️ Tidak ditemukan aksi swap dalam transaksi.")
            else:
                print(Fore.RED + "❌ Status response bukan OK.")
        else:
            print(Fore.RED + f"❌ Gagal cek status TX. Status code: {check_response.status_code}")
    except Exception as e:
        print(Fore.RED + f"❌ Error saat cek transaksi: {e}")

    report_trade_history(
        token=token,
        tx_hash=tx_hash_back,
        account=address,
        input_token_address=output_token_address,
        input_amount=in_amount,
        output_token_address=TOKENS["Monad"],
        output_amount=out_amount,
        chain_id=config["chainId"],
        proxy=proxy
    )


if __name__ == "__main__":
    wallets = get_wallets_from_pk("pk.txt")
    proxies = load_proxies()

    print(Fore.CYAN + "\n🔐 Apakah token sudah di-approve?")
    print("1. Belum (Lakukan approve dulu)\n2. Sudah (Langsung swap)")
    choice = input(Fore.YELLOW + "Masukkan pilihan (1/2): ")

    for i, (address, pk) in enumerate(wallets, 1):
        try:
            print(Fore.MAGENTA + f"\n=== Mulai proses untuk wallet [{i}] {mask_address(address)} ===")
            proxy = get_proxy(proxies)
            if choice == "1":
                print(Fore.CYAN + f"🔃 Mengirim approve TX untuk wallet {mask_address(address)}...")
                for name, token_address in TOKENS.items():
                    success = approve_token(
                        w3=w3,
                        private_key=pk,
                        token_address=token_address,
                        spender=SPENDER,
                        chain_id=config["chainId"]
                    )
                    if not success:
                        print(Fore.RED + f"    ❌ Gagal approve token {name}")
                    time.sleep(5)

            nonce = generate_nonce()
            timestamp = get_timestamp()
            message = create_sign_message(address, nonce, timestamp)
            signature = sign_message(pk, message)

            if not signature:
                print(Fore.RED + f"❌ Wallet [{i}] gagal melakukan sign message.")
                continue

            print(Fore.YELLOW + f"\n[{i}] 🔁 Auth: {mask_address(address)}")
            token = auth(address, message, signature, proxy)
            if not token:
                print(Fore.RED + f"❌ Wallet [{i}] gagal mendapatkan token auth.")
                continue

            # SWAP LOOP
            for cycle in range(1, swap_count + 1):
                print(Fore.BLUE + f"\n--- Swap Cycle {cycle} untuk wallet {mask_address(address)} ---")

                token_names = list(TOKENS.keys())
                token_names.remove("Monad")
                output_token_name = random.choice(token_names)
                output_token_address = TOKENS[output_token_name]

                print(Fore.MAGENTA + f"🎯 Target token: {output_token_name}")

                swap_data = get_price(token, address, proxy, output_token_address)
                if not swap_data:
                    print(Fore.RED + "❌ Gagal mendapatkan data swap forward.")
                    continue

                tx_hash = Swap_via_router(
                    w3=w3,
                    private_key=pk,
                    to=swap_data["to"],
                    value=swap_data["value"],
                    data=swap_data["data"],
                    chain_id=config["chainId"]
                )

                if not tx_hash:
                    print(Fore.RED + "❌ Gagal mengirim TX swap forward.")
                    continue

                time.sleep(5)

                report_trade_history(
                    token=token,
                    tx_hash=tx_hash,
                    account=address,
                    input_token_address=TOKENS["Monad"],
                    input_amount=swap_data.get("value", 0),
                    output_token_address=output_token_address,
                    output_amount=9000000000000000000,
                    chain_id=config["chainId"],
                    proxy=proxy
                )

                balance, decimals = check_token_balance(w3, address, output_token_address)
                if not balance or balance == 0:
                    print(Fore.YELLOW + "⚠️ Tidak ada saldo untuk swap balik.")
                    continue

                print(Fore.BLUE + f"🔁 Swap balik: seluruh saldo {balance:.6f} {output_token_name}")
                amount_wei = int(balance * (10 ** decimals))

                back_swap = get_price_back(token, address, output_token_address, amount_wei, proxy)
                if not back_swap:
                    print(Fore.RED + "❌ Gagal mendapatkan data untuk swap balik.")
                    continue
                tx_hash_back = Swap_via_router(
                    w3=w3,
                    private_key=pk,
                    to=back_swap["to"],
                    value=back_swap["value"],
                    data=back_swap["data"],
                    chain_id=config["chainId"]
                )

                if tx_hash_back:
                    handle_back_swap_report(tx_hash_back, output_token_address, address, token, proxy)
                    final_balance = w3.eth.get_balance(address) / 10**18
                    print(Fore.BLUE + f"💰 Saldo akhir MONAD: {final_balance:.6f}")
                else:
                    print(Fore.RED + "❌ Gagal mengirim TX swap balik.")

                time.sleep(random.uniform(2, 4))

        except Exception as e:
            print(Fore.RED + f"🚨 Error on wallet {i} ({address}): {e}")
            time.sleep(2)
