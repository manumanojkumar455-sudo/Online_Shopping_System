# ShopEasy — Online Shopping System

A Flask + SQLite college mini-project covering the customer shopping journey, seller/admin operations, delivery-agent handover, order tracking, and returns.

## 1. Requirements
- Python 3.10 or newer
- VS Code (or another Python IDE)
- Internet connection only if you want to configure optional SMTP email

## 2. Run the project
1. Extract the ZIP file.
2. Open the `online_shopping_system` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Create a virtual environment:
   - Windows: `py -m venv .venv`
   - macOS/Linux: `python3 -m venv .venv`
5. Activate it:
   - PowerShell: `.\.venv\Scripts\Activate.ps1`
   - Command Prompt: `.venv\Scripts\activate.bat`
   - macOS/Linux: `source .venv/bin/activate`
6. Install dependencies: `python -m pip install -r requirements.txt`
7. Start the app: `python app.py`
8. Open `http://127.0.0.1:5000` in your browser.

The SQLite database `shopping.db` and sample products/coupons are created automatically. If you already have the previous version's database, the app adds the new delivery/notification columns and upgrades old plain-text passwords to password hashes on startup.

## 3. Create the administrator account
Do not register an admin through the public registration form. In the VS Code terminal, with the virtual environment active, run:

`flask --app app create-admin`

Enter the admin name, email and a password of at least 8 characters when prompted. Then run `python app.py` and log in using those details. If your existing database contains an administrator account from the earlier version, that account keeps its admin role and its old password is converted to a secure hash. The old public registration shortcut has been removed; new admin accounts must be created from the terminal.

## 4. Customer test flow
1. Register a normal customer account (password must contain at least 8 characters).
2. Log in and search by product name, category or brand.
3. Open a product to view description, specifications, rating, price and available stock.
4. Add products to the cart and update quantities.
5. Checkout with a delivery address. Try coupon `WELCOME10` (10%) or `SAVE5` (5%).
6. Select UPI/Card Demo and use the simulated success/failure choice, or choose Cash on Delivery.
7. Open **My Orders** to view the order number, amount and status. Open **Notifications** to see order updates.

## 5. Seller and delivery-agent flow
1. Log in as admin and create a delivery-agent account from the Admin dashboard.
2. In Admin → Manage orders, change a new order's status to **Packed** using the order status controls only if present in your workflow. (If the order status is Confirmed, use the database admin page/status flow or the admin order status selector in the updated dashboard.)
3. Assign the packed order to a delivery agent using **Hand over**.
4. The delivery agent logs in using the account created by the admin.
5. The agent opens **Deliveries**, views the customer's delivery address, selects **Start delivery**, then **Mark as delivered** after delivery.
6. The customer can see each update in My Orders and Notifications.

## 6. Cancellation and return policy in this demo
- Customer cancellation is allowed while an order is **Confirmed** or **Packed**, before handover to the delivery agent.
- A return request can be submitted only after delivery and within **7 days** of the recorded delivery time.
- One active return request is allowed per order. Admin can approve or reject it.
- Demo payments are not automatically refunded. Cash on Delivery is recorded as pending payment.

## 7. Payment and notifications limitations
- Without gateway credentials, UPI/Card are **simulated demo payments**, not live payments. No card/bank information is collected.
- Optional Razorpay **test mode** is integrated. Install the requirements and set `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` as environment variables using Razorpay test keys. The checkout page then displays a Razorpay Test Mode button. The server creates the gateway order and verifies the payment signature before creating the shopping order. Never use live keys for a college demo, expose the secret key in frontend code, or commit keys to GitHub.
- Windows PowerShell example (replace with your own test credentials): `$env:RAZORPAY_KEY_ID="rzp_test_xxxxx"` and `$env:RAZORPAY_KEY_SECRET="your_test_secret"`. Start `python app.py` in that same terminal.
- In-app notifications are stored in SQLite and shown on the Notifications page.
- Email is optional. Configure environment variables `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_FROM`, and `SMTP_PASSWORD` to send notification emails. For Gmail, use an app password, not your normal account password.
- This project does not connect to a real courier company or generate live tracking links. The delivery-agent dashboard models the seller handover and delivery updates for the assignment.

## 8. Security notes
- Passwords are stored using Werkzeug password hashing.
- Public registration creates customer accounts only. Admin creates delivery-agent accounts.
- POST forms use a session-based CSRF token.
- Set a random `SECRET_KEY` environment variable before deployment. Use HTTPS and set `COOKIE_SECURE=1` behind HTTPS. Do not deploy Flask's development server or debug mode publicly.
- This is an educational project, not a production e-commerce platform.

## 9. Reset the database
Stop the server and delete `shopping.db`, then run `python app.py` again. This removes all users, orders, products added by you and notifications; the sample products and coupons will be recreated.
