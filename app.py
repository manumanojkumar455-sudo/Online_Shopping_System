from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, secrets, smtplib, hmac, hashlib
from email.message import EmailMessage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'shopping.db')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'development-only-change-this-secret-key'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'
RETURN_WINDOW_DAYS = 7

# Lightweight CSRF protection for every HTML form POST.
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']

@app.context_processor
def inject_globals():
    return {'cart_count': sum(int(q) for q in session.get('cart', {}).values()), 'csrf_token': csrf_token,
            'return_window_days': RETURN_WINDOW_DAYS, 'razorpay_key_id': os.environ.get('RAZORPAY_KEY_ID')}

@app.before_request
def protect_post_requests():
    if request.method == 'POST':
        supplied = request.form.get('_csrf_token', '') or request.headers.get('X-CSRF-Token', '')
        expected = session.get('_csrf', '')
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description='Security token missing or expired. Refresh the page and try again.')

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def add_column(conn, table, definition):
    name = definition.split()[0]
    existing = [r['name'] for r in conn.execute(f'PRAGMA table_info({table})')]
    if name not in existing:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {definition}')

def init_db():
    conn = get_db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer');
    CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL, brand TEXT NOT NULL, description TEXT NOT NULL, specifications TEXT NOT NULL, price REAL NOT NULL, rating REAL NOT NULL DEFAULT 4, stock INTEGER NOT NULL DEFAULT 0, image TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, discount_percent INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, order_number TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL, customer_name TEXT NOT NULL, address TEXT NOT NULL, payment_method TEXT NOT NULL, payment_status TEXT NOT NULL, subtotal REAL NOT NULL, discount REAL NOT NULL, total REAL NOT NULL, status TEXT NOT NULL DEFAULT 'Confirmed', created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, product_name TEXT NOT NULL, quantity INTEGER NOT NULL, unit_price REAL NOT NULL, FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(product_id) REFERENCES products(id));
    CREATE TABLE IF NOT EXISTS return_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, user_id INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Requested', created_at TEXT NOT NULL, FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id));
    ''')
    add_column(conn, 'orders', 'assigned_agent_id INTEGER REFERENCES users(id)')
    add_column(conn, 'orders', 'handed_over_at TEXT')
    add_column(conn, 'orders', 'delivered_at TEXT')
    # Upgrade passwords created by the earlier project version.
    for u in conn.execute('SELECT id,password FROM users').fetchall():
        if not (u['password'].startswith('scrypt:') or u['password'].startswith('pbkdf2:')):
            conn.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(u['password']), u['id']))
    if conn.execute('SELECT COUNT(*) FROM products').fetchone()[0] == 0:
        products = [
          ('Wireless Headphones','Electronics','SoundMax','Comfortable wireless headphones for everyday listening.','Bluetooth 5.3; 20-hour battery; USB-C charging',1299,4.4,18,'🎧'),
          ('Smart Watch','Electronics','TimePro','Smart watch with fitness and notification features.','1.8-inch display; step counter; water resistant',1799,4.2,12,'⌚'),
          ('Everyday Backpack','Fashion','UrbanCarry','Lightweight backpack for college and daily travel.','22 L capacity; padded straps; water-resistant fabric',899,4.3,25,'🎒'),
          ('Running Shoes','Footwear','RunFlex','Lightweight shoes suitable for daily walks and running.','Mesh upper; cushioned sole; lace-up closure',1199,4.1,9,'👟'),
          ('Coffee Mug','Home','DailySip','Reusable ceramic mug for tea or coffee.','350 ml; ceramic; microwave safe',249,4.5,40,'☕'),
          ('Bluetooth Speaker','Electronics','SoundMax','Portable speaker for music at home or outdoors.','10 W output; Bluetooth; rechargeable battery',999,4.0,0,'🔊'),
          ('Cotton T-Shirt','Fashion','BasicWear','Comfortable cotton T-shirt for everyday use.','100% cotton; regular fit; machine washable',399,4.2,30,'👕'),
          ('Desk Lamp','Home','BrightDesk','Compact LED lamp for study tables.','LED; adjustable neck; USB powered',549,4.1,14,'💡')]
        conn.executemany('INSERT INTO products(name,category,brand,description,specifications,price,rating,stock,image) VALUES(?,?,?,?,?,?,?,?,?)', products)
    conn.execute("INSERT OR IGNORE INTO coupons VALUES('WELCOME10',10,1)")
    conn.execute("INSERT OR IGNORE INTO coupons VALUES('SAVE5',5,1)")
    conn.commit(); conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning'); return redirect(url_for('login'))
        return fn(*a, **kw)
    return wrapper

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if 'user_id' not in session: return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('You do not have permission to access that page.', 'danger'); return redirect(url_for('index'))
            return fn(*a, **kw)
        return wrapper
    return deco

admin_required = role_required('admin')
delivery_required = role_required('delivery')

def now_text(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def notify(user_id, title, message):
    conn = get_db(); conn.execute('INSERT INTO notifications(user_id,title,message,created_at) VALUES(?,?,?,?)', (user_id,title,message,now_text())); conn.commit(); conn.close()
    # Optional SMTP email. In-app notification always works without SMTP configuration.
    host=os.environ.get('SMTP_HOST'); sender=os.environ.get('SMTP_FROM'); password=os.environ.get('SMTP_PASSWORD')
    if host and sender and password:
        conn=get_db(); user=conn.execute('SELECT email FROM users WHERE id=?',(user_id,)).fetchone(); conn.close()
        if user:
            try:
                msg=EmailMessage(); msg['Subject']=title; msg['From']=sender; msg['To']=user['email']; msg.set_content(message)
                with smtplib.SMTP(host, int(os.environ.get('SMTP_PORT','587'))) as server:
                    server.starttls(); server.login(sender,password); server.send_message(msg)
            except Exception as exc: app.logger.warning('Email notification failed: %s', exc)

def notify_admins(title, message):
    conn=get_db(); admin_ids=[r['id'] for r in conn.execute("SELECT id FROM users WHERE role='admin'").fetchall()]; conn.close()
    for admin_id in admin_ids: notify(admin_id,title,message)

def cart_details():
    cart_data=session.get('cart',{}); items=[]; subtotal=0; conn=get_db()
    for pid,qty in cart_data.items():
        product=conn.execute('SELECT * FROM products WHERE id=?',(int(pid),)).fetchone()
        if product:
            line=product['price']*int(qty); items.append({'product':product,'quantity':int(qty),'line_total':line}); subtotal+=line
    conn.close(); return items,subtotal

@app.route('/')
def index():
    q=request.args.get('q','').strip(); category=request.args.get('category','').strip(); brand=request.args.get('brand','').strip()
    conn=get_db(); sql='SELECT * FROM products WHERE 1=1'; params=[]
    if q: sql+=' AND (name LIKE ? OR category LIKE ? OR brand LIKE ?)'; params += [f'%{q}%']*3
    if category: sql+=' AND category=?'; params.append(category)
    if brand: sql+=' AND brand=?'; params.append(brand)
    sql+=' ORDER BY id DESC'; products=conn.execute(sql,params).fetchall()
    categories=conn.execute('SELECT DISTINCT category FROM products ORDER BY category').fetchall(); brands=conn.execute('SELECT DISTINCT brand FROM products ORDER BY brand').fetchall(); conn.close()
    return render_template('index.html',products=products,categories=categories,brands=brands,q=q,selected_category=category,selected_brand=brand)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn=get_db(); product=conn.execute('SELECT * FROM products WHERE id=?',(product_id,)).fetchone(); conn.close()
    if not product: flash('Product not found.','danger'); return redirect(url_for('index'))
    return render_template('product.html',product=product)

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        if not name or not email or len(password)<8:
            flash('Enter your name, a valid email, and a password with at least 8 characters.','danger'); return render_template('register.html')
        conn=get_db()
        try:
            conn.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'customer')",(name,email,generate_password_hash(password)))
            conn.commit(); flash('Account created. Please log in.','success'); return redirect(url_for('login'))
        except sqlite3.IntegrityError: flash('That email is already registered.','danger')
        finally: conn.close()
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        conn=get_db(); user=conn.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone(); conn.close()
        if user and check_password_hash(user['password'],password):
            session.clear(); session['user_id']=user['id']; session['name']=user['name']; session['role']=user['role']; session['cart']={}; csrf_token()
            flash(f"Welcome, {user['name']}!",'success')
            return redirect(url_for('admin_dashboard' if user['role']=='admin' else 'delivery_dashboard' if user['role']=='delivery' else 'index'))
        flash('Incorrect email or password.','danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); flash('You have been logged out.','info'); return redirect(url_for('index'))

@app.route('/cart')
def cart():
    items,subtotal=cart_details(); return render_template('cart.html',items=items,subtotal=subtotal)

@app.route('/cart/add/<int:product_id>',methods=['POST'])
def add_to_cart(product_id):
    try: quantity=max(1,int(request.form.get('quantity',1)))
    except ValueError: quantity=1
    conn=get_db(); product=conn.execute('SELECT * FROM products WHERE id=?',(product_id,)).fetchone(); conn.close()
    if not product: flash('Product not found.','danger')
    elif product['stock']<1: flash('This product is out of stock. Choose another product.','warning')
    elif quantity+int(session.get('cart',{}).get(str(product_id),0))>product['stock']: flash(f"Only {product['stock']} item(s) are available.",'warning')
    else:
        data=session.get('cart',{}); data[str(product_id)]=int(data.get(str(product_id),0))+quantity; session['cart']=data; flash('Product added to cart.','success')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart/update',methods=['POST'])
def update_cart():
    data=session.get('cart',{}); updated={}; conn=get_db()
    for pid,qty in data.items():
        try: new_qty=int(request.form.get('qty_'+pid,qty))
        except ValueError: new_qty=1
        product=conn.execute('SELECT stock FROM products WHERE id=?',(int(pid),)).fetchone()
        if product and new_qty>0: updated[pid]=min(new_qty,product['stock'])
    conn.close(); session['cart']=updated; flash('Cart updated.','success'); return redirect(url_for('cart'))

@app.route('/cart/remove/<int:product_id>',methods=['POST'])
def remove_from_cart(product_id):
    data=session.get('cart',{}); data.pop(str(product_id),None); session['cart']=data; flash('Product removed from cart.','info'); return redirect(url_for('cart'))

@app.route('/checkout',methods=['GET','POST'])
@login_required
def checkout():
    items,subtotal=cart_details()
    if not items: flash('Your cart is empty.','warning'); return redirect(url_for('index'))
    if request.method=='POST':
        name=request.form.get('customer_name','').strip(); address=request.form.get('address','').strip(); coupon_code=request.form.get('coupon','').strip().upper()
        payment_method=request.form.get('payment_method','Demo UPI'); payment_result=request.form.get('payment_result','success')
        if not name or len(address)<8: flash('Enter your name and a complete delivery address.','danger'); return render_template('checkout.html',items=items,subtotal=subtotal)
        conn=get_db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            discount_percent=0
            if coupon_code:
                coupon=conn.execute('SELECT * FROM coupons WHERE code=? AND active=1',(coupon_code,)).fetchone()
                if not coupon: raise ValueError('Invalid coupon code.')
                discount_percent=coupon['discount_percent']
            for item in items:
                current=conn.execute('SELECT stock FROM products WHERE id=?',(item['product']['id'],)).fetchone()
                if not current or current['stock']<item['quantity']: raise ValueError(f"Insufficient stock for {item['product']['name']}. Update your cart.")
            if payment_result=='failure': raise RuntimeError('Demo payment failed. No order was placed.')
            discount=round(subtotal*discount_percent/100,2); total=round(subtotal-discount,2)
            order_number='ORD-'+datetime.now().strftime('%y%m%d')+'-'+secrets.token_hex(3).upper()
            payment_status='Pending (Cash on Delivery)' if payment_method=='Cash on Delivery' else 'Paid (Demo)'
            cur=conn.execute("INSERT INTO orders(order_number,user_id,customer_name,address,payment_method,payment_status,subtotal,discount,total,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'Confirmed',?)",
                (order_number,session['user_id'],name,address,payment_method,payment_status,subtotal,discount,total,now_text()))
            oid=cur.lastrowid
            for item in items:
                p=item['product']; conn.execute('INSERT INTO order_items(order_id,product_id,product_name,quantity,unit_price) VALUES(?,?,?,?,?)',(oid,p['id'],p['name'],item['quantity'],p['price']))
                conn.execute('UPDATE products SET stock=stock-? WHERE id=?',(item['quantity'],p['id']))
            conn.commit()
        except (ValueError,RuntimeError) as exc:
            conn.rollback(); conn.close(); flash(str(exc),'danger'); return render_template('checkout.html',items=items,subtotal=subtotal)
        except Exception:
            conn.rollback(); conn.close(); app.logger.exception('Checkout failed'); flash('Could not place order. Please try again.','danger'); return render_template('checkout.html',items=items,subtotal=subtotal)
        conn.close(); session['cart']={}
        notify(session['user_id'],'Order confirmed',f'Your order {order_number} was placed. Total: ₹{total:.2f}. We will update you as it moves through delivery.')
        notify_admins('New customer order',f'Order {order_number} has been placed and is waiting for seller processing.')
        flash('Order placed successfully. This checkout uses demonstration payment, not a live gateway.','success')
        return redirect(url_for('order_detail',order_id=oid))
    return render_template('checkout.html',items=items,subtotal=subtotal)

@app.route('/payment/create', methods=['POST'])
@login_required
def payment_create():
    """Create a Razorpay TEST order. Requires merchant test keys in environment."""
    key_id=os.environ.get('RAZORPAY_KEY_ID'); key_secret=os.environ.get('RAZORPAY_KEY_SECRET')
    if not key_id or not key_secret:
        return jsonify(error='Razorpay test keys are not configured.'), 503
    try:
        import razorpay
        data=request.get_json(silent=True) or {}
        name=str(data.get('customer_name','')).strip(); address=str(data.get('address','')).strip(); coupon_code=str(data.get('coupon','')).strip().upper()
        if not name or len(address)<8: return jsonify(error='Enter a recipient name and complete delivery address.'), 400
        items,subtotal=cart_details()
        if not items: return jsonify(error='Your cart is empty.'), 400
        conn=get_db(); discount_percent=0
        if coupon_code:
            coupon=conn.execute('SELECT * FROM coupons WHERE code=? AND active=1',(coupon_code,)).fetchone()
            if not coupon: conn.close(); return jsonify(error='Invalid coupon code.'), 400
            discount_percent=coupon['discount_percent']
        for item in items:
            stock=conn.execute('SELECT stock FROM products WHERE id=?',(item['product']['id'],)).fetchone()
            if not stock or stock['stock']<item['quantity']: conn.close(); return jsonify(error=f"Insufficient stock for {item['product']['name']}"), 409
        conn.close(); total=round(subtotal-(subtotal*discount_percent/100),2)
        client=razorpay.Client(auth=(key_id,key_secret))
        gateway_order=client.order.create({'amount':int(round(total*100)),'currency':'INR','receipt':'shop-'+secrets.token_hex(6)})
        session['pending_razorpay']={'gateway_order_id':gateway_order['id'],'name':name,'address':address,'coupon':coupon_code,'subtotal':subtotal,'discount':round(subtotal*discount_percent/100,2),'total':total}
        return jsonify(key_id=key_id,order_id=gateway_order['id'],amount=gateway_order['amount'],currency='INR',name='ShopEasy',description='Online shopping order')
    except ImportError: return jsonify(error='Install the Razorpay package using pip install -r requirements.txt.'), 503
    except Exception as exc: app.logger.exception('Razorpay order creation failed'); return jsonify(error='Could not start payment. Check your test keys and try again.'), 502

@app.route('/payment/verify', methods=['POST'])
@login_required
def payment_verify():
    key_id=os.environ.get('RAZORPAY_KEY_ID'); key_secret=os.environ.get('RAZORPAY_KEY_SECRET')
    pending=session.get('pending_razorpay')
    if not key_id or not key_secret or not pending: return jsonify(error='Payment session expired or gateway is not configured.'), 400
    data=request.get_json(silent=True) or {}
    try:
        import razorpay
        client=razorpay.Client(auth=(key_id,key_secret))
        payment_data={'razorpay_order_id':data.get('razorpay_order_id'),'razorpay_payment_id':data.get('razorpay_payment_id'),'razorpay_signature':data.get('razorpay_signature')}
        if payment_data['razorpay_order_id'] != pending['gateway_order_id']: return jsonify(error='Payment order does not match this checkout.'), 400
        client.utility.verify_payment_signature(payment_data)
        payment=client.payment.fetch(payment_data['razorpay_payment_id'])
        if payment.get('status') != 'captured' or payment.get('order_id') != pending['gateway_order_id'] or int(payment.get('amount',0)) != int(round(pending['total']*100)) or payment.get('currency') != 'INR':
            return jsonify(error='Payment details could not be verified against this order.'), 400
        items,subtotal=cart_details(); conn=get_db(); conn.execute('BEGIN IMMEDIATE')
        for item in items:
            current=conn.execute('SELECT stock FROM products WHERE id=?',(item['product']['id'],)).fetchone()
            if not current or current['stock']<item['quantity']: conn.rollback(); conn.close(); return jsonify(error='Stock changed during payment. Contact the store with your payment reference.'), 409
        order_number='ORD-'+datetime.now().strftime('%y%m%d')+'-'+secrets.token_hex(3).upper()
        cur=conn.execute("INSERT INTO orders(order_number,user_id,customer_name,address,payment_method,payment_status,subtotal,discount,total,status,created_at) VALUES(?,?,?,?,'Razorpay Test Gateway','Paid (Razorpay Test)',?,?,?,'Confirmed',?)",(order_number,session['user_id'],pending['name'],pending['address'],subtotal,pending['discount'],pending['total'],now_text()))
        oid=cur.lastrowid
        for item in items:
            p=item['product']; conn.execute('INSERT INTO order_items(order_id,product_id,product_name,quantity,unit_price) VALUES(?,?,?,?,?)',(oid,p['id'],p['name'],item['quantity'],p['price'])); conn.execute('UPDATE products SET stock=stock-? WHERE id=?',(item['quantity'],p['id']))
        conn.commit(); conn.close(); session['cart']={}; session.pop('pending_razorpay',None)
        notify(session['user_id'],'Order confirmed',f'Your order {order_number} was paid using the Razorpay test gateway. Total: ₹{pending["total"]:.2f}.')
        notify_admins('New customer order',f'Order {order_number} has been placed and is waiting for seller processing.')
        return jsonify(redirect_url=url_for('order_detail',order_id=oid))
    except ImportError: return jsonify(error='Razorpay package is not installed.'), 503
    except Exception: app.logger.exception('Razorpay payment verification failed'); return jsonify(error='Payment verification failed. The order was not created.'), 400

@app.route('/orders')
@login_required
def orders():
    conn=get_db(); rows=conn.execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC',(session['user_id'],)).fetchall(); conn.close()
    return render_template('orders.html',orders=rows)

@app.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    conn=get_db(); order=conn.execute('SELECT * FROM orders WHERE id=?'+('' if session.get('role')=='admin' else ' AND user_id=?'),(order_id,) if session.get('role')=='admin' else (order_id,session['user_id'])).fetchone()
    if not order: conn.close(); flash('Order not found.','danger'); return redirect(url_for('orders'))
    items=conn.execute('SELECT * FROM order_items WHERE order_id=?',(order_id,)).fetchall(); agent=conn.execute('SELECT name,email FROM users WHERE id=?',(order['assigned_agent_id'],)).fetchone() if order['assigned_agent_id'] else None
    conn.close(); return render_template('order_detail.html',order=order,items=items,agent=agent)

@app.route('/order/<int:order_id>/cancel',methods=['POST'])
@login_required
def cancel_order(order_id):
    conn=get_db(); order=conn.execute('SELECT * FROM orders WHERE id=? AND user_id=?',(order_id,session['user_id'])).fetchone()
    if not order: flash('Order not found.','danger')
    elif order['status'] not in ('Confirmed','Packed'): flash('Cancellation is allowed only before the order is handed to the delivery agent.','warning')
    else:
        conn.execute('UPDATE products SET stock=stock+(SELECT quantity FROM order_items WHERE order_id=? AND product_id=products.id) WHERE id IN (SELECT product_id FROM order_items WHERE order_id=?)',(order_id,order_id))
        conn.execute("UPDATE orders SET status='Cancelled' WHERE id=?",(order_id,)); conn.commit(); notify(session['user_id'],'Order cancelled',f'Your order {order["order_number"]} was cancelled. Demo payments are not automatically refunded.'); flash('Order cancelled. Demo payments are not automatically refunded.','success')
    conn.close(); return redirect(url_for('order_detail',order_id=order_id))

@app.route('/order/<int:order_id>/return',methods=['POST'])
@login_required
def request_return(order_id):
    reason=request.form.get('reason','').strip(); conn=get_db(); order=conn.execute('SELECT * FROM orders WHERE id=? AND user_id=?',(order_id,session['user_id'])).fetchone()
    if not order: flash('Order not found.','danger')
    elif order['status']!='Delivered' or not order['delivered_at'] or datetime.now()-datetime.strptime(order['delivered_at'],'%Y-%m-%d %H:%M:%S')>timedelta(days=RETURN_WINDOW_DAYS): flash(f'Returns are accepted within {RETURN_WINDOW_DAYS} days of delivery.','warning')
    elif not reason: flash('Please provide a return reason.','danger')
    elif conn.execute("SELECT 1 FROM return_requests WHERE order_id=? AND status!='Rejected'",(order_id,)).fetchone(): flash('A return request already exists for this order.','warning')
    else:
        conn.execute('INSERT INTO return_requests(order_id,user_id,reason,created_at) VALUES(?,?,?,?)',(order_id,session['user_id'],reason,now_text())); conn.execute("UPDATE orders SET status='Return Requested' WHERE id=?",(order_id,)); conn.commit(); notify(session['user_id'],'Return request received',f'Your return request for {order["order_number"]} is awaiting review.'); flash('Return request submitted for review.','success')
    conn.close(); return redirect(url_for('order_detail',order_id=order_id))

@app.route('/notifications')
@login_required
def notifications():
    conn=get_db(); rows=conn.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC',(session['user_id'],)).fetchall(); conn.execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(session['user_id'],)); conn.commit(); conn.close(); return render_template('notifications.html',notifications=rows)

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn=get_db(); products=conn.execute('SELECT * FROM products ORDER BY id DESC').fetchall(); orders=conn.execute('SELECT o.*,u.name AS agent_name FROM orders o LEFT JOIN users u ON o.assigned_agent_id=u.id ORDER BY o.id DESC').fetchall()
    returns=conn.execute('SELECT rr.*,o.order_number,u.name AS customer_name FROM return_requests rr JOIN orders o ON rr.order_id=o.id JOIN users u ON rr.user_id=u.id ORDER BY rr.id DESC').fetchall()
    agents=conn.execute("SELECT id,name,email FROM users WHERE role='delivery' ORDER BY name").fetchall(); conn.close()
    return render_template('admin.html',products=products,orders=orders,returns=returns,agents=agents)

@app.route('/admin/agent/add',methods=['POST'])
@admin_required
def admin_add_agent():
    name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
    if not name or not email or len(password)<8: flash('Enter agent name, email and a password of at least 8 characters.','danger')
    else:
        conn=get_db()
        try: conn.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'delivery')",(name,email,generate_password_hash(password))); conn.commit(); flash('Delivery-agent account created.','success')
        except sqlite3.IntegrityError: flash('That email is already registered.','danger')
        finally: conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/add',methods=['POST'])
@admin_required
def admin_add_product():
    fields=[request.form.get(k,'').strip() for k in ('name','category','brand','description','specifications')]
    try: price=float(request.form.get('price','0')); rating=float(request.form.get('rating','4')); stock=int(request.form.get('stock','0'))
    except ValueError: flash('Price, rating and stock must be valid numbers.','danger'); return redirect(url_for('admin_dashboard'))
    if not all(fields) or price<0 or stock<0 or not 0<=rating<=5: flash('Complete all fields. Rating must be 0–5; price and stock cannot be negative.','danger'); return redirect(url_for('admin_dashboard'))
    conn=get_db(); conn.execute('INSERT INTO products(name,category,brand,description,specifications,price,rating,stock) VALUES(?,?,?,?,?,?,?,?)',(*fields,price,rating,stock)); conn.commit(); conn.close(); flash('Product added.','success'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/<int:product_id>/stock',methods=['POST'])
@admin_required
def admin_update_stock(product_id):
    try: stock=int(request.form.get('stock','0')); price=float(request.form.get('price','0'))
    except ValueError: flash('Enter valid stock and price.','danger'); return redirect(url_for('admin_dashboard'))
    if stock<0 or price<0: flash('Stock and price cannot be negative.','danger'); return redirect(url_for('admin_dashboard'))
    conn=get_db(); conn.execute('UPDATE products SET stock=?,price=? WHERE id=?',(stock,price,product_id)); conn.commit(); conn.close(); flash('Stock and price updated.','success'); return redirect(url_for('admin_dashboard'))


@app.route('/admin/order/<int:order_id>/status',methods=['POST'])
@admin_required
def admin_set_order_status(order_id):
    status=request.form.get('status','')
    if status not in ('Confirmed','Packed'):
        flash('Invalid seller status.','danger'); return redirect(url_for('admin_dashboard'))
    conn=get_db(); order=conn.execute('SELECT * FROM orders WHERE id=?',(order_id,)).fetchone()
    if order and order['status'] in ('Confirmed','Packed'):
        conn.execute('UPDATE orders SET status=? WHERE id=?',(status,order_id)); conn.commit()
        if status=='Packed': notify(order['user_id'],'Order packed',f'Your order {order["order_number"]} has been packed by the seller.')
        flash('Order status updated.','success')
    else: flash('This order can no longer be changed in the seller packing stage.','warning')
    conn.close(); return redirect(url_for('admin_dashboard'))

@app.route('/admin/order/<int:order_id>/handover',methods=['POST'])
@admin_required
def admin_handover(order_id):
    try: agent_id=int(request.form.get('agent_id','0'))
    except ValueError: agent_id=0
    conn=get_db(); agent=conn.execute("SELECT id FROM users WHERE id=? AND role='delivery'",(agent_id,)).fetchone(); order=conn.execute('SELECT * FROM orders WHERE id=?',(order_id,)).fetchone()
    if not order or order['status']!='Packed' or not agent: flash('Pack the order and choose a valid delivery agent before handover.','danger')
    else:
        conn.execute("UPDATE orders SET assigned_agent_id=?,status='Handed to Delivery Agent',handed_over_at=? WHERE id=?",(agent_id,now_text(),order_id)); conn.commit(); notify(order['user_id'],'Order handed to delivery agent',f'Order {order["order_number"]} has been handed to the delivery agent.'); notify(agent_id,'New delivery assigned',f'Order {order["order_number"]} is assigned to you.'); flash('Order handed over to delivery agent.','success')
    conn.close(); return redirect(url_for('admin_dashboard'))

@app.route('/admin/return/<int:return_id>/status',methods=['POST'])
@admin_required
def admin_update_return(return_id):
    status=request.form.get('status','')
    if status not in ('Approved','Rejected'): flash('Invalid return decision.','danger'); return redirect(url_for('admin_dashboard'))
    conn=get_db(); rr=conn.execute('SELECT * FROM return_requests WHERE id=?',(return_id,)).fetchone()
    if rr and rr['status']=='Requested':
        conn.execute('UPDATE return_requests SET status=? WHERE id=?',(status,return_id))
        conn.execute("UPDATE orders SET status=? WHERE id=?",('Returned' if status=='Approved' else 'Delivered',rr['order_id']))
        if status=='Approved':
            conn.execute('UPDATE products SET stock=stock+(SELECT quantity FROM order_items WHERE order_id=? AND product_id=products.id) WHERE id IN (SELECT product_id FROM order_items WHERE order_id=?)',(rr['order_id'],rr['order_id']))
        conn.commit(); notify(rr['user_id'],'Return request '+status.lower(),f'Your return request was {status.lower()}.')
    conn.close(); flash('Return request updated.','success'); return redirect(url_for('admin_dashboard'))

@app.route('/delivery')
@delivery_required
def delivery_dashboard():
    conn=get_db(); assigned=conn.execute('SELECT * FROM orders WHERE assigned_agent_id=? ORDER BY id DESC',(session['user_id'],)).fetchall(); conn.close(); return render_template('delivery.html',orders=assigned)

@app.route('/delivery/order/<int:order_id>/status',methods=['POST'])
@delivery_required
def delivery_update(order_id):
    status=request.form.get('status','')
    if status not in ('Out for Delivery','Delivered'): flash('Invalid delivery update.','danger'); return redirect(url_for('delivery_dashboard'))
    conn=get_db(); order=conn.execute('SELECT * FROM orders WHERE id=? AND assigned_agent_id=?',(order_id,session['user_id'])).fetchone()
    if not order: flash('This order is not assigned to your account.','danger')
    elif status=='Out for Delivery' and order['status']!='Handed to Delivery Agent': flash('The order must be handed over before delivery starts.','warning')
    elif status=='Delivered' and order['status']!='Out for Delivery': flash('Mark the order out for delivery first.','warning')
    else:
        delivered=now_text() if status=='Delivered' else None
        conn.execute('UPDATE orders SET status=?,delivered_at=COALESCE(?,delivered_at) WHERE id=?',(status,delivered,order_id)); conn.commit(); notify(order['user_id'],'Order status updated',f'Your order {order["order_number"]} is now: {status}.'); flash('Delivery status updated.','success')
    conn.close(); return redirect(url_for('delivery_dashboard'))

@app.cli.command('create-admin')
def create_admin():
    """Create an administrator account securely from the terminal."""
    init_db()
    import getpass
    name=input('Admin name: ').strip(); email=input('Admin email: ').strip().lower(); password=getpass.getpass('Admin password (8+ chars): ')
    if not name or not email or len(password)<8: print('Invalid details.'); return
    conn=get_db()
    try: conn.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'admin')",(name,email,generate_password_hash(password))); conn.commit(); print('Admin account created.')
    except sqlite3.IntegrityError: print('That email already exists.')
    finally: conn.close()

@app.errorhandler(400)
def bad_request(error): return render_template('error.html',code=400,message=getattr(error,'description','Bad request')),400

if __name__=='__main__':
    init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG','0')=='1')
