# @title 🚀 Shein Product Monitor (Initial All Products Alert + Ongoing New) - Men (Sorted by Newest)
import time
import sqlite3
import requests
import json
import threading
import random
import sys
from datetime import datetime
from flask import Flask
import hashlib  # For hashing if no ID

# --- ⚙️ CONFIGURATION ---
BOT_TOKEN = "8071143720:AAHcI4pKQ0IJK5gAENfD4nEXSUqhI7mXvaU"  # Filled
CHAT_IDS = ["7445191377"]  # Added new chat ID

MEN_API_URL = "https://www.sheinindia.in/api/category/sverse-5939-37961?fields=SITE&currentPage=0&pageSize=45&format=json&query=%3Anewest%3Agenderfilter%3AMen&sort=9&gridColumns=2&facets=genderfilter%3AMen&segmentIds=15%2C18%2C9%2C21&cohortIds=value%7Cmen&customerType=Existing&includeUnratedProducts=false&advfilter=true&platform=Desktop&showAdsOnNextPage=false&is_ads_enable_plp=true&displayRatings=true&store=shein"


API_URLS = [
    {'name': 'Men', 'url': MEN_API_URL},
    
]

CHECK_DELAY = 2 # Fast: 10s refresh
MAX_RETRIES = 1
DB_FILE = "shein_server.db"

# --- PROXY CONFIG: Disabled ---
PROXIES = None

# --- FLASK SERVER (For Health Checks) ---
app = Flask('')

@app.route('/')
def home():
    return f"Shein Monitor Running. Refresh: {CHECK_DELAY}s. Initial Alert: All Current Products (Men ) - Sorted by Newest."


def run_flask():
    app.run(host='0.0.0.0', port=8080, debug=False)

def start_server():
    t = threading.Thread(target=run_flask)
    t.daemon = True
    t.start()

# --- THE BOT ---
class SheinMonitor:
    def __init__(self):
        self.setup_db()
        self.session = requests.Session()
        if PROXIES:
            self.session.proxies.update(PROXIES)
            print("🔒 Proxies enabled.")
        else:
            print("🔓 Direct connection.")
        self.consecutive_failures = 0
        self.test_telegram()  # Test alert on startup
        print("🤖 Monitor Ready: Initial ALL products alert + New drops with Code/Name/Link (Men) - Sorted by Newest.")

    def setup_db(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id TEXT,
                url TEXT,
                name TEXT,
                seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id)
            )
        ''')
        
        # Check and add 'category' column if it doesn't exist (for upgrade)
        cursor.execute("PRAGMA table_info(products)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'category' not in columns:
            cursor.execute("ALTER TABLE products ADD COLUMN category TEXT")
            print("🔧 DB upgraded: Added 'category' column.")
        
        # Update PRIMARY KEY to include category if needed (for multi-category support)
        try:
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='products'")
            create_sql = cursor.fetchone()[0]
            if 'PRIMARY KEY (id)' in create_sql and 'category' in columns:
                # Drop and recreate with new PK (safe for monitor, as data is simple)
                cursor.execute("DROP TABLE IF EXISTS products")
                cursor.execute('''
                    CREATE TABLE products (
                        id TEXT,
                        category TEXT,
                        url TEXT,
                        name TEXT,
                        seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (id, category)
                    )
                ''')
                print("🔧 DB recreated with composite PK for categories.")
        except:
            pass  # If already good, skip
        
        self.conn.commit()

    def is_new_product(self, product_id, category):
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM products WHERE id = ? AND category = ?", (product_id, category))
        return cursor.fetchone() is None

    def save_product(self, product_id, url, name, category):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO products (id, category, url, name) VALUES (?, ?, ?, ?)",
            (product_id, category, url, name)
        )
        self.conn.commit()

    def test_telegram(self):
        """Send test message to confirm bot works"""
        test_msg = "<b>🧪 SHEIN Monitor Started! (Men - Newest Sort)</b>\n------------------------------\n✅ Bot active. Initial all products alert coming next...\n⏰ <i>{}</i>".format(datetime.now().strftime('%H:%M:%S'))
        self._send_telegram_raw(test_msg)
        print("📱 Test alert sent to Telegram.")

    def _send_telegram_raw(self, msg):
        """Raw Telegram send helper - Send to all CHAT_IDS"""
        api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "text": msg, 
            "parse_mode": "HTML",
            "disable_web_page_preview": False
        }
        for chat_id in CHAT_IDS:
            payload["chat_id"] = chat_id
            try:
                resp = requests.post(api_url, data=payload, timeout=10)
                if resp.status_code == 200:
                    print(f"✅ Telegram OK for {chat_id}.")
                else:
                    print(f"❌ Telegram Error for {chat_id}: {resp.status_code} - {resp.text}")
            except Exception as e:
                print(f"❌ Telegram Fail for {chat_id}: {e}")

    def send_telegram_alert(self, products_list, is_initial=False, category=''):
        """Batch alert: Code, Name, SHEIN Link - FAST (Initial: All current)"""
        if not products_list:
            return
        
        title = f"<b>🚨 {'INITIAL ALL PRODUCTS' if is_initial else 'NEW DROPS'}! ({category} SVERSE)</b>"
        msg_parts = [title + "\n------------------------------\n"]
        for item in products_list:
            msg_parts.append(f"🛍 <b>{item['name'][:80]}...</b>\n")  # Short name
            msg_parts.append(f"🆔 Code: {item['id']}\n")  # Product code/ID
            msg_parts.append(f"🔗 <a href='{item['url']}'>SHEIN LINK</a>\n\n")  # Direct link
        msg_parts.append(f"⏰ <i>{datetime.now().strftime('%H:%M:%S')}</i> | Total: {len(products_list)}")
        msg = "".join(msg_parts)
        
        self._send_telegram_raw(msg)
        alert_type = "INITIAL" if is_initial else "NEW"
        print(f"🚨 {alert_type} Batch Alert ({category}): {len(products_list)} items with codes/names/links sent!")

    def fetch_products_from_api(self, api_url):
        """Fetch & parse (Fixed for direct 'products')"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://www.sheinindia.in/sheinverse/c/sverse-5939-37961',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Origin': 'https://www.sheinindia.in',
            'Connection': 'keep-alive'
        }
        
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(api_url, headers=headers, timeout=15)
                data = response.json()
                print(f"📡 Status: {response.status_code} | Total: {data.get('totalResults', 0)}")
                if response.status_code == 403:
                    print(f"⚠️ 403 attempt {attempt+1}. Retry...")
                    time.sleep(10 * (attempt + 1))
                    continue
                response.raise_for_status()
                
                products = []
                if 'products' in data and isinstance(data['products'], list):
                    for item in data['products']:
                        prod_id = str(item.get('id', ''))
                        if not prod_id:
                            url = item.get('url', '')
                            prod_id = hashlib.md5(url.encode()).hexdigest()[:16]
                        
                        name = item.get('name', 'Unknown')
                        url = f"https://www.sheinindia.in{item.get('url', '')}" if item.get('url') else f"https://www.sheinindia.in/p/{prod_id}"
                        
                        products.append({
                            'id': prod_id,
                            'name': name,
                            'url': url
                        })
                    print(f"✅ {len(products)} products parsed.")
                else:
                    print("⚠️ No products list. Summary:", json.dumps(data, indent=2)[:200] + "...")
                
                self.consecutive_failures = 0
                return products
            except requests.exceptions.RequestException as e:
                print(f"❌ Fetch Error {attempt+1}: {e}")
                time.sleep(random.uniform(5, 10))
        
        self.consecutive_failures += 1
        return []

    def start(self):
        print(f"🚀 Started: Scanning every {CHECK_DELAY}s (Men - Newest Sort)")
        first_run = True

        while True:
            try:
                for cat_info in API_URLS:
                    category = cat_info['name']
                    api_url = cat_info['url']
                    products = self.fetch_products_from_api(api_url)
                    print(f"🔍 {category}: Found {len(products)} items.")
                    
                    current_products = []  # All for initial
                    new_products = []  # Only new for ongoing

                    for item in products:
                        if self.is_new_product(item['id'], category):
                            self.save_product(item['id'], item['url'], item['name'], category)
                            new_products.append(item)
                        current_products.append(item)  # Always add for initial alert
                    
                    if first_run:
                        # On first run: Alert ALL current products (even if 4 now)
                        self.send_telegram_alert(current_products, is_initial=True, category=category)
                        print(f"✅ Initial Alert ({category}): {len(current_products)} all products sent with codes/links.")
                    else:
                        if new_products:
                            self.send_telegram_alert(new_products, category=category)  # Only new
                        else:
                            print(f"💤 {category}: No new.")
                

            except KeyboardInterrupt:
                print("🛑 Stopped.")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
            
            print(f"⏳ Scan in {CHECK_DELAY}s...")
            first_run = False
            time.sleep(CHECK_DELAY)

if __name__ == "__main__":
    start_server()
    bot = SheinMonitor()
    bot.start()