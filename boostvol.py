import os
import requests
import time
import uuid
import json
from eth_account import Account
from web3.auto import w3
from eth_account.messages import encode_defunct, encode_typed_data
from decimal import Decimal
from dotenv import load_dotenv
from eip712.messages import EIP712Message, EIP712Type
import websockets
import asyncio
import ssl
import time  
import math


# Load environment variables from .env file
load_dotenv()

# Fetch the private key from .env file
private_key = os.getenv("PRIVATE_KEY")
if not private_key:
    raise Exception("PRIVATE_KEY environment variable not set in .env file!")

# Initialize Ethereum account
account = Account.from_key(private_key)
address = account.address
CHAIN_ID = 421614
domain = "testnet.predicthub.io"

# Generate a unique x-device-id using uuid
x_device_id = str(uuid.uuid4())

# Define maximum amount (cap) and target price

# Track total amount bought
total_bought = Decimal(0)

# API prod URLs
NONCE_URL = "https://clob.predicthub.io/auth/crypto/nonce"
LOGIN_URL = "https://clob.predicthub.io/auth/crypto/login"
ORDER_URL = "https://clob.predicthub.io/order"
MARKET_URL = "https://clob.predicthub.io/market-group"
WS_URL = "wss://pf.predicthub.io/v1"  # WebSocket URL


AA_WALLET_ADDRESS = os.getenv("AA_WALLET_ADDRESS")
if not AA_WALLET_ADDRESS:
    raise Exception("AA_WALLET_ADDRESS environment variable not set in .env file!")




# Set the market ID as a variable
#market_group_id = "cd89cd49-92b7-11ef-b3fe-fa70d9e443fb"  # The specific market ID you want to trade in

# Fetch market and token price from the market response
def fetch_market_price_and_token_info(market_group_id, token_id):
    url = f"{MARKET_URL}/{market_group_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        market_data = response.json()
        
        # Iterate through the markets
        for market in market_data['data']['markets']:
            # Iterate through outcomes within each market
            for outcome in market['outcomes']:
                if outcome['id'] == token_id:
                    price = Decimal(outcome.get('price', 0))  # Extract price from the outcome
                    print(f"Price for token {token_id} is {price}")
                    return price  # Return the price once found
        raise Exception(f"Token ID {token_id} not found in the provided market group.")
    else:
        raise Exception(f"Failed to fetch market data: {response.status_code}, {response.content.decode('utf-8')}")
# Step 1: Fetch nonce from PredictHub API
def get_nonce():
    headers = {
        'Content-Type': 'application/json',
        'x-device-id': x_device_id
    }
    body = {
        "chain_id": CHAIN_ID,
        "domain": domain,
        "version": 1,
        "wallet": address
    }
    
    print(f"Fetching nonce with headers: {headers}, body: {body}")
    resp = requests.post(NONCE_URL, headers=headers, json=body)
    
    print(f"Nonce Response: {resp.status_code}, {resp.content.decode('utf-8')}")
    
    if resp.status_code >= 400:
        raise Exception('Error fetching nonce')
    
    return resp.json()['data']

# Step 2: Sign the SIWE message using the nonce data
def sign_siwe_message(nonce_data):
    domain = nonce_data['domain']
    nonce = nonce_data['nonce']
    issued_at = nonce_data['issued_at']

    siwe_message = f"""{domain} wants you to sign in with your Ethereum account:\n{address}\n\nI accept the Terms of Service of PredictHub\n\nURI: {domain}\nVersion: 1\nChain ID: {CHAIN_ID}\nNonce: {nonce}\nIssued At: {issued_at}"""
    
    print(f"Signing message: {siwe_message}")
    
    message = encode_defunct(text=siwe_message)
    signed_message = w3.eth.account.sign_message(message, private_key=private_key)
    
    signature = signed_message.signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature
    
    print(f"Generated Signature with 0x prefix: {signature}")
    return signature

# Step 3: Login and get the authentication token
def login(signature):
    headers = {
        'Content-Type': 'application/json',
        'x-device-id': x_device_id
    }
    data = {
        "address": address,
        "signature": signature
    }
    
    print(f"Logging in with headers: {headers}, body: {data}")
    response = requests.post(LOGIN_URL, headers=headers, json=data)
    
    print(f"Login Response: {response.status_code}, {response.content.decode('utf-8')}")

    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        raise Exception("Login failed")
## Step 4: Fetch the market_id, token_id, and outcome_name for a specific market group
def get_market_and_token_info(market_group_id):
    url = f"{MARKET_URL}/{market_group_id}"
    response = requests.get(url)
    
    print(f"Market Response: {response.status_code}, {response.content.decode('utf-8')}")

    if response.status_code == 200:
        market_data = response.json()
        markets = market_data['data']['markets']

        # Print markets and their outcomes
        for j, market in enumerate(markets):
            # Print market ID and question field
            print(f"Market {j}: ID: {market['id']} | Question: {market['question']}")
            
            # Print each outcome in the market
            for i, outcome in enumerate(market['outcomes']):
                print(f"   {i}. Outcome Name: {outcome['name']}, Token ID: {outcome['id']}")

        # Allow user to select the market by index
        market_index = int(input("Select the market by index (0, 1, 2, ...): "))
        selected_market = markets[market_index]
        market_id = selected_market['id']

        # Allow user to select the outcome by index
        outcome_index = int(input("Select the outcome by index (0, 1, 2, ...): "))
        selected_outcome = selected_market['outcomes'][outcome_index]
        token_id = selected_outcome['id']
        outcome_name = selected_outcome['name']

        print(f"Selected Market ID: {market_id}, Outcome Name: {outcome_name}, Token ID: {token_id}")
        return token_id, outcome_name, market_id
    else:
        raise Exception("Failed to fetch market data")
# Step 5: Generate signature for the order using EIP-712 structured data
def sign_order(order_data, private_key):
    DOMAIN = {
        "name": "PredictHub Exchange",
        "version": "1",
        "chainId": CHAIN_ID,                
        "verifyingContract": "0x342A5D8FdB25704F1817f07445115a3adF22210D"
    }

    TYPES = {
        "Order": [
            {"name": "salt", "type": "uint256"},
            {"name": "maker", "type": "address"},
            {"name": "signer", "type": "address"},
            {"name": "taker", "type": "address"},
            {"name": "tokenId", "type": "uint256"},
            {"name": "makerAmount", "type": "uint256"},
            {"name": "takerAmount", "type": "uint256"},
            {"name": "expiration", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "feeRateBps", "type": "uint256"},
            {"name": "side", "type": "uint8"},
            {"name": "signatureType", "type": "uint8"}
        ]
    }

    # Prepare the EIP-712 message to be signed
    message = {
        "types": TYPES,
        "domain": DOMAIN,
        "primaryType": "Order",
        "message": order_data
    }

    print(f"Signing message: {message}")

    # Encode the structured data (EIP-712) for signing
    signable_message = encode_typed_data(domain_data=DOMAIN, message_types=TYPES, message_data=order_data)
    # Sign the structured message
    signed_message = Account.sign_message(signable_message, private_key)

    # Convert the signature to a hex string with a '0x' prefix
    signature_hex = signed_message.signature.hex()
    if not signature_hex.startswith("0x"):
        signature_hex = '0x' + signature_hex

    return signature_hex

# Step 6: Place a market order based on user input
def place_market_order(auth_token, token_id, outcome_name, amount_market, side_type,market_id,market_group_id):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}',
        'x-chain-id': str(CHAIN_ID),
        'x-device-id': x_device_id
    }

    nonce_value = int(time.time() * 1000)   # Use current timestamp as nonce
    # Log the calculated amount
    print(f"market_group_id: {market_group_id} and token id: {token_id}")

    market_price = fetch_market_price_and_token_info(market_group_id, token_id)

    if market_price is None:
        raise ValueError(f"Failed to fetch price for token_id: {token_id}")
        
    is_buy = (side_type == "BUY")
    maker_amount = Decimal(amount_market) * Decimal(1e6)
    taker_amount = maker_amount if is_buy else Decimal(0)

    if is_buy:
        amount = (Decimal(amount_market) / market_price * Decimal(1e8)).quantize(Decimal('1.'))
    else:
        amount = maker_amount

    # Log the calculated amount
    print(f"Amount before signing: {amount}")

    # Step 2: Prepare the order_data before signing
    order_data = {
        'side': 0 if is_buy else 1,  # Include side for signature, remove before sending to API
        'expiration': 0,
        'feeRateBps': 0,
        'maker': AA_WALLET_ADDRESS,
        'makerAmount': str(maker_amount),
        'nonce': 0,
        'salt': str(nonce_value),
        'signatureType': 2,  # AA signature type
        'signer': address,
        'taker': '0x0000000000000000000000000000000000000000',
        'takerAmount': str(taker_amount),
        'tokenId': token_id
    }

    # Step 3: Sign the order with the correct amount
    signature_hex = sign_order(order_data, private_key)
    

 # Step 4: Prepare the API call data, now including 'amount'
    api_order_data = {
        'expiration': 0,
        'fee_rate_bps': 0,
        'maker': AA_WALLET_ADDRESS,
        'maker_amount': str(maker_amount),
        'nonce': 0,
        'salt': str(nonce_value),
        'signature_type': 2,  # AA signature type
        'signer': address,
        'taker': '0x0000000000000000000000000000000000000000',
        'taker_amount': str(taker_amount),
        'token_id': token_id, 
        'amount': str(amount),
        'type': 'MARKET',
        'buy': is_buy,
        'price': str((market_price * Decimal(1e4)).quantize(Decimal('1.'))),
        'market_id': str(market_id),
        'signature': str(signature_hex)
    }

    # Log the amount in API request to ensure consistency
    print(f"Amount in API call: {api_order_data['amount']}")

    # Send the order to the API
    print(f"Placing market order with headers: {headers}, body: {api_order_data}")
    
    response = requests.post(ORDER_URL, headers=headers, json=api_order_data)
    
    print(f"Order Response: {response.status_code}, {response.content.decode('utf-8')}")

    time.sleep(0.5)

    return response

def fetch_order_log(auth_token, order_id):
    order_log_url = f"https://clob.predicthub.io/order-log/{order_id}"
    
    headers = {
        'Accept': 'application/json, application/problem+json',
        'Authorization': f'Bearer {auth_token}'
    }
        # Print request details
    print(f"Request URL: {order_log_url}")
    print(f"Request Headers: {headers}")
    response = requests.get(order_log_url, headers=headers)
    print(f"Order Log for Order ID {order_id}: {response.json()}")
    if response.status_code == 200:
        print(f"Order Log for Order ID {order_id}: {response.json()}")
    else:
        print(f"Failed to fetch order log. Status Code: {response.status_code}, Response: {response.content.decode('utf-8')}")


async def execute_buy_sell_loop(auth_token, token_id, market_id, outcome_name, average_amount, max_iterations,market_group_id):
    ssl_context = ssl._create_unverified_context()  # Assuming SSL verification is disabled for testing/development
    iteration = 0  # Counter to track the number of loops
    max_sell_retries = 10  # Maximum retries for the sell order

    while iteration < max_iterations:
        try:
            async with websockets.connect(WS_URL, ssl=ssl_context) as websocket:
                print(f"Connected to WebSocket for token ID: {token_id}")

                # Subscription message for the ticker
                subscription_message = json.dumps({
                    "type": "subscribe",
                    "id": str(uuid.uuid4()),
                    "params": [f"{token_id}@ticker"]
                })
                await websocket.send(subscription_message)
                print(f"Sent subscription message: {subscription_message}")

                buy_price = None  # Store the price used for the buy order
                cycle_complete = False  # Track full buy-sell cycle status

                while not cycle_complete:  # Only one buy-sell cycle per iteration
                    message = await websocket.recv()
                    data = json.loads(message)

                    # Check if message type is ticker and matches the token
                    if data.get("type") == "ticker" and not buy_price:
                        payload = data.get("payload", {})
                        if payload.get("token") == token_id:
                            # Set and log the buy price
                            price = Decimal(payload.get("price", 0)) / Decimal(1e8)  # Convert to USD equivalent
                            buy_price = price
                            print(f"Set buy price for token {token_id}: {buy_price}")

                            # Calculate amount for the buy order
                            amount_market_buy = round(float(average_amount))
                            print(f"Calculated amount_market for BUY: {amount_market_buy}")

                            # Place a buy order and check if it's successful
                            print("Placing buy order...")
                            buy_order_response = place_market_order(auth_token, token_id, outcome_name, amount_market_buy, "BUY", market_id,market_group_id)
                            
                            if buy_order_response.status_code == 200:
                                print(f"Buy order placed successfully: {buy_order_response.content}")
                                response_data = buy_order_response.json()

                                # Extract the amount from the "output" field
                                 # Calculate amount for the sell order using the saved buy_price
                                amount_market_sell = Decimal(average_amount) / (buy_price / Decimal(1e4))
                                amount_market_sell = math.floor(float(amount_market_sell))  # Convert to float and round
                                print(f"Calculated amount_market for SELL using buy price {buy_price}: {amount_market_sell}")
                                await asyncio.sleep(3)  # Short delay before placing the sell order

                                # Attempt to place the sell order with retries
                                sell_success = False
                                sell_retries = 0
                                while not sell_success and sell_retries < max_sell_retries:
                                    print(f"Attempting sell order, try {sell_retries + 1} of {max_sell_retries}...")
                                    sell_order_response = place_market_order(auth_token, token_id, outcome_name, amount_market_sell, "SELL", market_id,market_group_id)
                                    
                                    if sell_order_response.status_code == 200:
                                        print("Sell order placed successfully.")
                                        sell_success = True
                                        cycle_complete = True
                                        iteration += 1  # Increment only after successful buy and sell
                                        print(f"Completed {iteration} of {max_iterations} iterations.")
                                    else:
                                        print("Sell order failed. Retrying...")
                                        sell_retries += 1
                                        amount_market_sell = math.floor(amount_market_sell * 0.99)  # Reduce by 1% and round down
                                        print(f"Reduced amount_market_sell by 1%: {amount_market_sell}")

                                        await asyncio.sleep(2)  # Wait before retrying

                                if not sell_success:
                                    print("Sell order failed after maximum retries. Moving to next cycle.")
                                    break  # Exit the current cycle after max retries

                            else:
                                print("Buy order failed. Retrying buy order.")

        except websockets.exceptions.ConnectionClosedError as e:
            print(f"WebSocket connection closed: {str(e)}. Reconnecting...")
            await asyncio.sleep(5)  # Wait before attempting to reconnect
        except Exception as e:
            print(f"Error: {str(e)}")
            break

        # Check if the max_iterations has been reached after each complete buy-sell cycle
        if iteration >= max_iterations:
            print("Max iterations reached. Exiting loop.")
            break
# Main function to initiate the buy-sell loop 
def main():
    nonce_data = get_nonce()
    signature = sign_siwe_message(nonce_data)
    auth_token = login(signature)
    
    market_group_id = str(input("Market Group ID:"))
    
    token_id, outcome_name, market_id = get_market_and_token_info(market_group_id)
    # User input for average amount per order
    average_amount = Decimal(input("Enter the average amount in USD for each order: "))
    max_iterations = int(input("Max loop: "))
    # Start the buy-sell loop with the WebSocket listener
    asyncio.run(execute_buy_sell_loop(auth_token, token_id, market_id, outcome_name, average_amount,max_iterations,market_group_id))
    
if __name__ == "__main__":
    main()