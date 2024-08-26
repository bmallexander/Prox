import requests
from app import db, Plan, create_app

app = create_app()

# Proxmox API credentials
PROXMOX_API_URL = 'https://37.114.37.146:8006/api2/json'
PROXMOX_USER = 'root@pam'
PROXMOX_PASSWORD = 'voa7rARiToPO6h4rK37A'

def get_proxmox_token():
    response = requests.post(
        f"{PROXMOX_API_URL}/access/ticket",
        data={'username': PROXMOX_USER, 'password': PROXMOX_PASSWORD},
        verify=False  # Bypass SSL certificate verification
    )
    response.raise_for_status()
    return response.json()

def add_plans():
    plans = [
        {'name': 'Basic Plan', 'description': 'Basic server plan with essential features.', 'price': 100, 'memory': 2048, 'disk': 20, 'cores': 2},
        {'name': 'Standard Plan', 'description': 'Standard server plan with additional features.', 'price': 200, 'memory': 4096, 'disk': 40, 'cores': 4},
        {'name': 'Premium Plan', 'description': 'Premium server plan with all features.', 'price': 300, 'memory': 8192, 'disk': 80, 'cores': 8},
    ]

    with app.app_context():
        for plan_data in plans:
            plan = Plan(
                name=plan_data['name'],
                description=plan_data['description'],
                price=plan_data['price'],
                memory=plan_data['memory'],
                disk=plan_data['disk'],
                cores=plan_data['cores']
            )
            db.session.add(plan)
        db.session.commit()
        print('Plans added successfully!')

if __name__ == "__main__":
    add_plans()
