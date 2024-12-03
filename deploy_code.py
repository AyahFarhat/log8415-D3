import paramiko
import boto3

class InstanceDiscovery:
    def __init__(self, region='us-east-1'):
        """
        Initialize AWS EC2 resource for IP discovery.
        """
        self.ec2_resource = boto3.resource('ec2', region_name=region)
    
    def get_instance_ip_by_name(self, instance_name):
        """
        Get the public IP address of an instance by its Name tag.
        """
        try:
            filters = [{'Name': 'tag:Name', 'Values': [instance_name]},
                           {'Name': 'instance-state-name', 'Values': ['running']}]
            instances = list(self.ec2_resource.instances.filter(Filters=filters))
            
            if not instances:
                print(f"No instance found with name: {instance_name}")
                return None
            
            instance = instances[0]
            if instance.state['Name'] == 'running':
                return instance.public_ip_address
            else:
                print(f"Instance {instance_name} is not in running state.")
                return None
        except Exception as e:
            print(f"Error fetching IP for instance {instance_name}: {e}")
            return None



def deploy_and_run_app(public_ip, pem_key_path, app_filename):
    key = paramiko.RSAKey.from_private_key_file(pem_key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(public_ip, username='ubuntu', pkey=key)
    # Upload the FastAPI app
    sftp = ssh.open_sftp()
    sftp.put(app_filename, f"/home/ubuntu/{app_filename}")
    sftp.close()
    # Install dependencies and run FastAPI app
    commands = [
        "sudo apt update",
        "sudo apt install -y python3-pip",
        "pip3 install fastapi uvicorn httpx boto3 mysql-connector-python",
        "pip3 show uvicorn",
        'sudo fuser -k 8080/tcp',
        f"nohup python3 -m uvicorn {app_filename.split('.')[0]}:app --host 0.0.0.0 --port 8080 > {app_filename.split('.')[0]}_log.out 2>&1 &"

    ]
    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        print(f"Executing: {command}")
        print(stdout.read().decode())
        print(stderr.read().decode())
    ssh.close()


PEM_KEY_PATH = 'mysql-cluster-key.pem'

# Initialize instance discovery
discovery = InstanceDiscovery()


GATEKEEPER_IP = discovery.get_instance_ip_by_name('gatekeeper')
if not GATEKEEPER_IP:
    raise Exception("Gatekeeper Server IP could not be retrieved. Ensure the instance is running and tagged correctly.")

PROXY_SERVER_IP = discovery.get_instance_ip_by_name('mysql-proxy')
if not PROXY_SERVER_IP:
    raise Exception("Proxy Server IP could not be retrieved. Ensure the instance is running and tagged correctly.")

TRUSTED_HOST_IP = discovery.get_instance_ip_by_name('trusted-host')
if not TRUSTED_HOST_IP:
    raise Exception("Trusted host IP could not be retrieved. Ensure the instance is running and tagged correctly.")

print(f"Gatekeeper IP: {GATEKEEPER_IP}")
print(f"Proxy Server IP: {PROXY_SERVER_IP}")
print(f"Trusted Host IP: {TRUSTED_HOST_IP}")

deploy_and_run_app(public_ip=GATEKEEPER_IP, pem_key_path=PEM_KEY_PATH, app_filename='gatekeeper_app.py')
deploy_and_run_app(public_ip=TRUSTED_HOST_IP, pem_key_path=PEM_KEY_PATH, app_filename='trusted_host_app.py')
deploy_and_run_app(public_ip=PROXY_SERVER_IP, pem_key_path=PEM_KEY_PATH, app_filename='proxy_server_app.py')
