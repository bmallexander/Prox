from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room

import requests
import urllib3
import secrets
import string


# Disable SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



OXAPAY_API_URL = 'https://api.oxapay.com/v1'
OXAPAY_API_KEY = 'your_oxapay_api_key'

socketio = SocketIO(app, cors_allowed_origins="*")


# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    credits = db.relationship('UserCredits', uselist=False, backref='user')
    is_admin = db.Column(db.Boolean, default=False)
    servers = db.relationship('Node', backref='user', lazy=True)

# Plan model
class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    memory = db.Column(db.Integer, nullable=False)
    disk = db.Column(db.Integer, nullable=False)
    cores = db.Column(db.Integer, nullable=False)
    max_cores = db.Column(db.Integer, nullable=True)
    max_memory = db.Column(db.Integer, nullable=True)
    max_disk = db.Column(db.Integer, nullable=True)

# Node model
class Node(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vmid = db.Column(db.Integer, unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)

# Ticket model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tickets', lazy=True))

# UserCredits model
class UserCredits(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credits = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def generate_random_password(length=12):
    """Generate a random password with a mix of letters and digits."""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for i in range(length))


def connect_libvirt():
    """Connect to the local libvirt daemon."""
    return libvirt.open('qemu:///system')

def create_vm(name, memory, disk, cores, password):
    conn = connect_libvirt()
    try:
        # Define VM XML configuration
        xml_desc = f"""
        <domain type='kvm'>
          <name>{name}</name>
          <memory unit='KiB'>{memory * 1024}</memory>
          <vcpu placement='static'>{cores}</vcpu>
          <os>
            <type arch='x86_64' machine='pc-i440fx-2.9'>hvm</type>
            <boot dev='hd'/>
          </os>
          <disk type='file' device='disk'>
            <driver name='qemu' type='qcow2'/>
            <source file='/var/lib/libvirt/images/{name}.qcow2'/>
            <target dev='vda' bus='virtio'/>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
          </disk>
          <interface type='network'>
            <mac address='52:54:00:aa:bb:cc'/>
            <source network='default'/>
            <model type='virtio'/>
          </interface>
          <graphics type='vnc' port='-1' autoport='yes'/>
          <video>
            <model type='cirrus' vram='9216' heads='1'/>
          </video>
          <input type='mouse' bus='ps2'/>
          <sound model='ich6'/>
          <memballoon model='virtio'/>
        </domain>
        """
        conn.createXML(xml_desc, libvirt.VIR_DOMAIN_CREATE_NON_PERSIST)
    finally:
        conn.close()


def get_vm_list():
    conn = connect_libvirt()
    try:
        vms = conn.listAllDomains()
        return [{'name': vm.name(), 'id': vm.ID()} for vm in vms]
    finally:
        conn.close()


def create_payment(amount, currency='USD', description='Payment'):
    headers = {
        'Authorization': f'Bearer {OXAPAY_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'amount': amount,
        'currency': currency,
        'description': description
    }
    response = requests.post(f'{OXAPAY_API_URL}/create-payment', json=payload, headers=headers, verify=False)
    response.raise_for_status()
    print(response.json())
    return response.json()

def verify_payment(payment_id):
    headers = {
        'Authorization': f'Bearer {OXAPAY_API_KEY}',
    }
    response = requests.get(f'{OXAPAY_API_URL}/payment/{payment_id}', headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

@app.route('/my_servers')
@login_required
def my_servers():
    user_nodes = Node.query.filter_by(user_id=current_user.id).all()
    return render_template('my_servers.html', nodes=user_nodes)


@app.route('/')
@login_required
def index():
    plans = Plan.query.all()
    user_credits = current_user.credits.credits if current_user.credits else 0
    return render_template('index.html', plans=plans, user_credits=user_credits)


@app.route('/buy/<int:plan_id>', methods=['POST'])
@login_required
def buy(plan_id):
    plan = Plan.query.get_or_404(plan_id)
    user_credits = UserCredits.query.filter_by(user_id=current_user.id).first()

    if not user_credits:
        user_credits = UserCredits(user_id=current_user.id, credits=0)
        db.session.add(user_credits)
        db.session.commit()

    if user_credits.credits < plan.price:
        flash('You do not have enough credits to purchase this plan.')
        return redirect(url_for('index'))

    user_credits.credits -= plan.price
    db.session.commit()

    try:
        next_vmid = str(len(get_vm_list()) + 1)
        root_password = generate_random_password()

        create_vm(
            name=f"{current_user.username}-{plan.name}",
            memory=plan.memory,
            disk=plan.disk,
            cores=plan.cores,
            password=root_password
        )

        new_node = Node(
            name=f'{current_user.username}-{plan.name}',
            description=plan.description,
            plan_id=plan.id,
            user_id=current_user.id,
            vmid=next_vmid,
            password=root_password,  # Save the generated password
            ip_address='N/A'  # IP address would be determined differently in KVM
        )
        db.session.add(new_node)
        db.session.commit()

        flash('Server created and configured successfully!')
    except Exception as e:
        flash(f'Error occurred while creating server: {str(e)}')
    
    return redirect(url_for('index'))


    
    
@app.route('/user_vms', methods=['GET'])
@login_required
def user_vms():
    try:
        vms = get_vm_list()
        user_vms = [vm for vm in vms if vm['name'].startswith(current_user.username)]
        return jsonify([{'id': vm['id'], 'name': vm['name']} for vm in user_vms])
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/add_balance', methods=['GET', 'POST'])
@login_required
def add_balance():
    if request.method == 'POST':
        amount = int(request.form['amount'])
        if amount <= 0:
            flash('Amount must be greater than zero.')
            return redirect(url_for('add_balance'))
        
        payment_response = create_payment(amount * 100)
        print(payment_response)
        
        if 'payment_url' in payment_response:
            payment_url = payment_response['payment_url']
            return redirect(payment_url)
        else:
            flash('Failed to get payment URL. Please try again.')
            return redirect(url_for('add_balance'))
    
    return render_template('add_balance.html')

@app.route('/payment-callback')
@login_required
def payment_callback():
    payment_id = request.args.get('payment_id')
    payment_status = verify_payment(payment_id)
    
    if payment_status['status'] == 'success':
        amount = payment_status['amount']
        user_credits = UserCredits.query.filter_by(user_id=current_user.id).first()
        
        if not user_credits:
            user_credits = UserCredits(user_id=current_user.id, credits=0)
            db.session.add(user_credits)
        
        user_credits.credits += amount // 100
        db.session.commit()
        
        flash('Payment successful! Credits have been added to your account.')
    else:
        flash('Payment failed. Please try again.')

    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and/or password.')
    
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Create Proxmox user with generated credentials
        create_proxmox_user(username, password)
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/ticket', methods=['GET', 'POST'])
@login_required
def ticket():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        ticket = Ticket(title=title, description=description, user_id=current_user.id)
        db.session.add(ticket)
        db.session.commit()
        flash('Ticket submitted successfully!')
        return redirect(url_for('ticket'))
    
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    return render_template('ticket.html', tickets=tickets)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.is_admin and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login failed. Check your username and/or password.')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin_add_credits/<int:user_id>', methods=['POST'])
@login_required
def admin_add_credits(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    amount = int(request.form['amount'])
    user_credits = UserCredits.query.filter_by(user_id=user_id).first()
    
    if not user_credits:
        user_credits = UserCredits(user_id=user_id, credits=0)
        db.session.add(user_credits)
    
    user_credits.credits += amount
    db.session.commit()
    
    flash('Credits added successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_ban_user/<int:user_id>', methods=['POST'])
@login_required
def admin_ban_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash('User banned successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_plans')
@login_required
def admin_plans():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    plans = Plan.query.all()
    return render_template('admin_plans.html', plans=plans)

@app.route('/admin_add_plan', methods=['GET', 'POST'])
@login_required
def admin_add_plan():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        cores = int(request.form['cores'])
        memory = int(request.form['memory'])
        disk = int(request.form['disk'])
        max_cores = request.form.get('max_cores', type=int)
        max_memory = request.form.get('max_memory', type=int)
        max_disk = request.form.get('max_disk', type=int)

        new_plan = Plan(name=name, description=description, price=price, cores=cores, memory=memory, disk=disk,
                        max_cores=max_cores, max_memory=max_memory, max_disk=max_disk)
        db.session.add(new_plan)
        db.session.commit()

        flash('Plan added successfully!')
        return redirect(url_for('admin_plans'))

    return render_template('admin_add_plan.html')

@app.route('/admin_edit_plan/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_plan(plan_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    plan = Plan.query.get_or_404(plan_id)
    
    if request.method == 'POST':
        plan.name = request.form['name']
        plan.description = request.form['description']
        plan.price = float(request.form['price'])
        plan.cores = int(request.form['cores'])
        plan.memory = int(request.form['memory'])
        plan.disk = int(request.form['disk'])
        plan.max_cores = request.form.get('max_cores', type=int)
        plan.max_memory = request.form.get('max_memory', type=int)
        plan.max_disk = request.form.get('max_disk', type=int)

        db.session.commit()

        flash('Plan updated successfully!')
        return redirect(url_for('admin_plans'))
    
    return render_template('admin_edit_plan.html', plan=plan)

@app.route('/admin_delete_plan/<int:plan_id>', methods=['POST'])
@login_required
def admin_delete_plan(plan_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    plan = Plan.query.get_or_404(plan_id)
    db.session.delete(plan)
    db.session.commit()

    flash('Plan deleted successfully!')
    return redirect(url_for('admin_plans'))

@app.route('/manage_container/<int:vmid>', methods=['POST'])
@login_required
def manage_container(vmid):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))

    action = request.form.get('action')
    if action not in ['start', 'stop', 'restart']:
        flash('Invalid action.')
        return redirect(url_for('my_servers'))

    # Check if the VM ID belongs to the current user
    node = Node.query.filter_by(vmid=vmid, user_id=current_user.id).first()
    if not node:
        flash('You do not have permission to manage this container.')
        return redirect(url_for('my_servers'))

    try:
        token = get_proxmox_token()
        csrf_token = token['data']['CSRFPreventionToken']
        ticket = token['data']['ticket']

        actions_map = {
            'start': f"{PROXMOX_API_URL}/nodes/proxmox/lxc/{vmid}/status/start",
            'stop': f"{PROXMOX_API_URL}/nodes/proxmox/lxc/{vmid}/status/stop",
            'restart': f"{PROXMOX_API_URL}/nodes/proxmox/lxc/{vmid}/status/restart"
        }

        response = requests.post(
            actions_map[action],
            headers={
                'Authorization': f'PVEAuthCookie={ticket}',
                'CSRFPreventionToken': csrf_token
            },
            verify=False
        )
        response.raise_for_status()
        flash(f'Container {action}ed successfully!')
    except requests.exceptions.HTTPError as err:
        error_message = f"HTTP error occurred: {err}\nResponse content: {err.response.text}"
        print(error_message)
        flash(f'An error occurred while {action}ing the container: {error_message}')
    except Exception as err:
        print(f"Unexpected error occurred: {err}")
        flash(f'An unexpected error occurred while {action}ing the container: {err}')

    return redirect(url_for('my_servers'))





@socketio.on('connect')
def handle_connect():
    token = get_proxmox_token()
    emit('connected', {'status': 'connected', 'ticket': token['data']['ticket'], 'csrf_token': token['data']['CSRFPreventionToken']})

@socketio.on('exec_command')
def handle_exec_command(data):
    vmid = data.get('vmid')
    command = data.get('command')
    ticket = data.get('ticket')
    csrf_token = data.get('csrf_token')

    if not vmid or not command or not ticket or not csrf_token:
        emit('exec_response', {'error': 'Invalid parameters'})
        return

    # Assume SSH-based command execution as Proxmox API might not support direct command execution
    try:
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname='your-proxmox-host', username='root', password='your-password')

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()

        emit('exec_response', {'output': output, 'error': error})

    except Exception as e:
        emit('exec_response', {'error': str(e)})





if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
