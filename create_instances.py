import boto3
import time
import paramiko
import os
import requests

ROOT_PASSWORD='password'

def create_user_and_grant_privileges(ssh_client, db_user, db_password):
    """
    Create a MySQL user and grant privileges on the current instance.
    """
    user_commands = [
        # Create the user with specified password
        f"sudo mysql -u root -p'{ROOT_PASSWORD}' -e \"CREATE USER '{db_user}'@'%' IDENTIFIED BY '{db_password}';\"",
        # Grant all privileges on Sakila database
        f"sudo mysql -u root -p'{ROOT_PASSWORD}' -e \"GRANT ALL PRIVILEGES ON sakila.* TO '{db_user}'@'%';\"",
        # Flush privileges to apply changes
        f"sudo mysql -u root -p'{ROOT_PASSWORD}' -e \"FLUSH PRIVILEGES;\""
    ]
    for cmd in user_commands:
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        print(f"User Configuration: {cmd}")
        print(stdout.read().decode())
        print(stderr.read().decode())
class MySQLClusterSetup:
    def __init__(self, region='us-east-1'):
        """
        Initialize AWS resources and configurations
        """
        # Get public IP address of my machine
        self.my_ip = requests.get('https://api.ipify.org').text + "/32"
        
        # AWS Clients
        self.ec2 = boto3.client('ec2', region_name=region)
        self.ec2_resource = boto3.resource('ec2', region_name=region)
        
        # Key pair configuration
        self.key_pair_name = 'mysql-cluster-key'
        self.key_pair_path = f'./{self.key_pair_name}.pem'
        
        self.instance_configs = {
            'standalone_instances': [
                {'name': 'mysql-manager', 'type': 't2.micro'},
                {'name': 'mysql-worker-1', 'type': 't2.micro'},
                {'name': 'mysql-worker-2', 'type': 't2.micro'}
            ],
            'proxy_instances': [
                {'name': 'mysql-proxy', 'type': 't2.large'}
            ],
            'gatekeeper_instances': [
                {'name': 'gatekeeper', 'type': 't2.large'},
                {'name': 'trusted-host', 'type': 't2.large'}
            ]
        }
        
        self.security_groups = {
            'mysql_cluster_sg': { 
                'name': 'mysql-cluster-sg',
                'description': 'Security group for MySQL cluster',
                'ingress_rules': [
                    {'port': 3306, 'protocol': 'tcp', 'source_sg': 'proxy_sg'},
                    {'port': 3306, 'protocol': 'tcp', 'source_sg': 'mysql_cluster_sg'},
                    {'port': 22, 'protocol': 'tcp', 'cidr': self.my_ip},  # Allow SSH from machine's IP
                ]
            },
            'proxy_sg': {
                'name': 'mysql-proxy-sg',
                'description': 'Security group for MySQL proxy',
                'ingress_rules': [
                    {'port': 8080, 'protocol': 'tcp', 'source_sg': 'trusted_host_sg'},
                    {'port': 22, 'protocol': 'tcp', 'cidr': self.my_ip}, 
                ],
            },
            'trusted_host_sg': {
                'name': 'trusted-host-sg',
                'description': 'Security group for Trusted Host',
                'ingress_rules': [
                    {'port': 8080, 'protocol': 'tcp', 'source_sg': 'gatekeeper_sg'},
                    {'port': 22, 'protocol': 'tcp', 'cidr': self.my_ip}, 
                ],
            },
            'gatekeeper_sg': {
                'name': 'gatekeeper-sg',
                'description': 'Security group for Gatekeeper and Trusted Host',
                'ingress_rules': [
                    {'port': 22, 'protocol': 'tcp', 'cidr': self.my_ip}, 
                    {'port': 8080, 'protocol': 'tcp', 'cidr': '0.0.0.0/0'},  # Open 8080 for external traffic
                ]
            }
        }


    def create_key_pair(self):
        """
        Create an EC2 key pair and save the private key
        """
        try:
            # Check if key pair already exists
            self.ec2.describe_key_pairs(KeyNames=[self.key_pair_name])
            print(f"Key pair {self.key_pair_name} already exists.")
            return
        except self.ec2.exceptions.ClientError:
            # Create new key pair
            key_pair = self.ec2.create_key_pair(KeyName=self.key_pair_name)
            
            # Save private key with restricted permissions
            with open(self.key_pair_path, 'w') as key_file:
                key_file.write(key_pair['KeyMaterial'])
            
            os.chmod(self.key_pair_path, 0o400)
            print(f"Key pair {self.key_pair_name} created and saved.")

    def create_security_groups(self):
        """
        Create security groups for different components
        """
        security_group_ids = {}
        
        for sg_key, sg_config in self.security_groups.items():
            try:
                
                vpc = list(self.ec2_resource.vpcs.filter(Filters=[{'Name': 'isDefault', 'Values': ['true']}]))[0]
                
                
                security_group = vpc.create_security_group(
                    GroupName=sg_config['name'],
                    Description=sg_config['description']
                )            
                
                security_group_ids[sg_key] = security_group.id
                print(f"Security group {sg_config['name']} created.")
            
            except Exception as e:
                print(f"Error creating security group {sg_config['name']}: {e}")
        
        
        for sg_key, sg_config in self.security_groups.items():
            try:
                security_group = self.ec2_resource.SecurityGroup(security_group_ids[sg_key])
                
                for rule in sg_config['ingress_rules']:
                    # Handle ingress from CIDR
                    if 'cidr' in rule:
                        security_group.authorize_ingress(
                            IpProtocol=rule['protocol'],
                            FromPort=rule['port'],
                            ToPort=rule['port'],
                            CidrIp=rule['cidr']
                        )
                    # Handle ingress from another security group
                    elif 'source_sg' in rule:
                        source_sg_id = security_group_ids.get(rule['source_sg'])
                        if not source_sg_id:
                            raise Exception(f"Source security group {rule['source_sg']} not found.")
                        
                        security_group.authorize_ingress(
                            IpPermissions=[
                                {
                                    'IpProtocol': rule['protocol'],
                                    'FromPort': rule['port'],
                                    'ToPort': rule['port'],
                                    'UserIdGroupPairs': [
                                        {'GroupId': source_sg_id}
                                    ]
                                }
                            ]
                        )
            
            except Exception as e:
                print(f"Error adding rules to security group {sg_config['name']}: {e}")
        
        return security_group_ids

    def launch_instances(self, security_group_ids):

        launched_instances = {}
        
        # Combine all instance configurations
        all_instances = (
            self.instance_configs['standalone_instances'] + 
            self.instance_configs['proxy_instances'] + 
            self.instance_configs['gatekeeper_instances']
        )
        
        iam_instance_profile = {'Name': 'EMR_EC2_DefaultRole'}
        
        for instance_config in all_instances:
            try:
                # Determine security group based on instance type
                if 'trusted-host' in instance_config['name']:
                    sg_id = security_group_ids['trusted_host_sg']
                elif 'proxy' in instance_config['name']:
                    sg_id = security_group_ids['proxy_sg']
                elif 'mysql-' in instance_config['name']:
                    sg_id = security_group_ids['mysql_cluster_sg']
                else:
                    sg_id = security_group_ids['gatekeeper_sg']
                
                # Launch instance
                instance = self.ec2_resource.create_instances(
                    ImageId='ami-005fc0f236362e99f',
                    InstanceType=instance_config['type'],
                    KeyName=self.key_pair_name,
                    MinCount=1,
                    MaxCount=1,
                    SecurityGroupIds=[sg_id],
                    IamInstanceProfile=iam_instance_profile,
                    TagSpecifications=[
                        {
                            'ResourceType': 'instance',
                            'Tags': [{'Key': 'Name', 'Value': instance_config['name']}]
                        }
                    ]
                )[0]
                
                instance.wait_until_running()
                instance.reload()
                
                launched_instances[instance_config['name']] = {
                    'instance': instance,
                    'public_ip': instance.public_ip_address
                }
                
                print(f"Instance {instance_config['name']} launched with IP {instance.public_ip_address}")
            
            except Exception as e:
                print(f"Error launching instance {instance_config['name']}: {e}")
        
        return launched_instances
    


    def install_mysql_and_sakila(self, instances):
        """
        Install MySQL and Sakila database on specific instances with replication setup
        """  
        mysql_manager = instances['mysql-manager']
        mysql_worker_1 = instances['mysql-worker-1']
        mysql_worker_2 = instances['mysql-worker-2']
        
        role_to_server_id = {
            'mysql-manager': 3,
            'mysql-worker-1': 1,
            'mysql-worker-2': 2
        }

        def configure_mysql_replication(master_instance, slave_instances):
            """
            Configure MySQL replication between master and slave nodes
            """
            try:
                # SSH connection to master
                master_ssh = paramiko.SSHClient()
                master_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                private_key = paramiko.RSAKey.from_private_key_file(self.key_pair_path)
                
                master_ssh.connect(
                    hostname=master_instance['public_ip'],
                    username='ubuntu',
                    pkey=private_key
                )

                # Create replication user on master
                replication_user_commands = [
                    # Create replication user
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "CREATE USER \'replication_user\'@\'%\' IDENTIFIED WITH \'mysql_native_password\' BY \'replication_password\';"',
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "ALTER USER \'replication_user\'@\'%\' IDENTIFIED WITH \'mysql_native_password\' BY \'replication_password\';"',
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "GRANT REPLICATION SLAVE ON *.* TO \'replication_user\'@\'%\';"',
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "FLUSH PRIVILEGES;"',
                    
                    # Lock tables and get master status
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "FLUSH TABLES WITH READ LOCK;"',
                    f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "SHOW MASTER STATUS;"'
                ]


                for cmd in replication_user_commands:
                    stdin, stdout, stderr = master_ssh.exec_command(cmd)
                    print(f"Master Configuration: {cmd}")
                    print(stdout.read().decode())
                    print(stderr.read().decode())

                # Capture master status for each slave
                master_status_cmd = f"sudo mysql -u root -p'{ROOT_PASSWORD}' -e \"SHOW MASTER STATUS;\" | awk 'NR==2 {{print $1, $2}}'"

                stdin, stdout, stderr = master_ssh.exec_command(master_status_cmd)
                master_status = stdout.read().decode().strip().split()
                log_file, log_pos = master_status[0], master_status[1]

                # Configure each slave
                for slave_instance in slave_instances:
                    # SSH connection to slave
                    slave_ssh = paramiko.SSHClient()
                    slave_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    slave_ssh.connect(
                        hostname=slave_instance['public_ip'],
                        username='ubuntu',
                        pkey=private_key
                    )

                    # Stop slave and configure replication
                    slave_commands = [
                        # Stop slave process
                        f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "STOP SLAVE;"',
                        
                        # Configure slave to use the updated master settings
                        f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "CHANGE MASTER TO MASTER_HOST=\'{master_instance["public_ip"]}\', '
                        f'MASTER_USER=\'replication_user\', '
                        f'MASTER_PASSWORD=\'replication_password\', '
                        f'MASTER_LOG_FILE=\'{log_file}\', '
                        f'MASTER_LOG_POS={log_pos};"',
                        
                        # Start slave process
                        f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "START SLAVE;"',
                        
                        # Check slave status
                        f"sudo mysql -u root -p'{ROOT_PASSWORD}' -e 'SHOW SLAVE STATUS\\G'"
                    ]

                    for cmd in slave_commands:
                        stdin, stdout, stderr = slave_ssh.exec_command(cmd)
                        print(f"Slave Configuration: {cmd}")
                        print(stdout.read().decode())
                        print(stderr.read().decode())

                    slave_ssh.close()

                # Unlock tables on master
                master_ssh.exec_command(f'sudo mysql -u root -p\'{ROOT_PASSWORD}\' -e "UNLOCK TABLES;"')
                master_ssh.close()

            except Exception as e:
                print(f"Error setting up MySQL replication: {e}")

        for name, instance_info in instances.items():
            if name not in ['mysql-manager', 'mysql-worker-1', 'mysql-worker-2']:
                continue
            print('--------------------------------------------------------------------------------------')
            try:
                # SSH connection setup
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                private_key = paramiko.RSAKey.from_private_key_file(self.key_pair_path)
                
                ssh.connect(
                    hostname=instance_info['public_ip'],
                    username='ubuntu',
                    pkey=private_key
                )
                server_id = role_to_server_id.get(name)
                if server_id is None:
                    raise ValueError(f"Unknown server role: {name}")    
                print("server id: ", server_id)

                # MySQL and Sakila installation 
                install_commands = [
                    f'sudo debconf-set-selections <<< "mysql-server mysql-server/root_password password {ROOT_PASSWORD}"',
                    f'sudo debconf-set-selections <<< "mysql-server mysql-server/root_password_again password {ROOT_PASSWORD}"',
                    'sudo apt-get update',
                    'sudo apt-get install -y mysql-server wget unzip',
                    'sudo systemctl start mysql',
                    'sudo systemctl enable mysql',
                    r"sudo sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf",
                    r'sudo sed -i "/\[mysqld\]/a log_bin = /var/log/mysql/mysql-bin.log" /etc/mysql/mysql.conf.d/mysqld.cnf',
                    rf'sudo sed -i "/\[mysqld\]/a server-id = {server_id}" /etc/mysql/mysql.conf.d/mysqld.cnf',
                    'sudo systemctl restart mysql',
                    'wget https://downloads.mysql.com/docs/sakila-db.zip -O /tmp/sakila-db.zip',
                    'unzip /tmp/sakila-db.zip -d /tmp',
                    f'mysql -u root -p"{ROOT_PASSWORD}" < /tmp/sakila-db/sakila-schema.sql',
                    f'mysql -u root -p"{ROOT_PASSWORD}" < /tmp/sakila-db/sakila-data.sql',
                    f'mysql -u root -p"{ROOT_PASSWORD}" -e "USE sakila; SHOW TABLES;"',
                    f'mysql -u root -p"{ROOT_PASSWORD}" -e "DELETE FROM mysql.user WHERE User=\'\';"',
                    f'mysql -u root -p"{ROOT_PASSWORD}" -e "FLUSH PRIVILEGES;"',
                ]
                
                for cmd in install_commands:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    print(f"Executing on {name}: {cmd}")
                    print(stdout.read().decode())
                    print(stderr.read().decode())             
                
                create_user_and_grant_privileges(ssh, 'user', 'password')
                
                ssh.close()
                
            except Exception as e:
                print(f"Error setting up MySQL on {name}: {e}")
        
        # Set up replication after all instances are configured
        configure_mysql_replication(
            mysql_manager, 
            [mysql_worker_1, mysql_worker_2]
        )
    
    def setup_mysql_cluster(self):
        """
        Main method to set up the entire MySQL cluster infrastructure
        """
        try:
            # Create key pair
            self.create_key_pair()
            
            # Create security groups
            security_group_ids = self.create_security_groups()
            print("security_group_ids", security_group_ids)
            
            # Launch instances
            instances = self.launch_instances(security_group_ids)
            print("instances", instances)

            #Wait for instances to be fully initialized
            time.sleep(60)
            
            #Install MySQL and Sakila
            self.install_mysql_and_sakila(instances)
                        
            print("MySQL Cluster Setup Complete!")
            
            return instances
        
        except Exception as e:
            print(f"Error in MySQL cluster setup: {e}")
            return None

def secure_instance(ssh_client, instance_name, gatekeeper_ip):
    """
    Secure the instance by setting up a firewall, removing unused services, 
    and disabling unnecessary ports based on instance type.
    """
    try:
        print(f"Securing instance: {instance_name}")
        
        # Firewall (IPTables) Configuration
        firewall_commands = ["sudo iptables -F"]  # Flush existing rules
        
        if instance_name == "gatekeeper":
            firewall_commands += [
                "sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT",  # Allow external traffic on port 8080
                "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",  # Allow SSH
                "sudo iptables -A INPUT -j DROP",  # Drop all other incoming traffic
            ]
        elif instance_name == "trusted-host":
            if not gatekeeper_ip:
                raise ValueError("Gatekeeper IP is required for Trusted Host firewall rules")
            firewall_commands += [
                f"sudo iptables -A INPUT -p tcp --dport 8080 -s {gatekeeper_ip} -j ACCEPT",  # Allow Gatekeeper traffic only
                "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",  # Allow SSH
                "sudo iptables -A INPUT -j DROP",  # Drop all other incoming traffic
            ]

        # Disable Unnecessary Ports
        disable_ports_commands = [
            "sudo ufw default deny incoming",  # Deny all incoming traffic by default
            "sudo ufw allow 22",  # Allow SSH
        ]
        
        if instance_name == "gatekeeper":
            disable_ports_commands += ["sudo ufw allow 8080"]  # Allow port 8080 for Gatekeeper
        elif instance_name == "trusted-host":
            # Trusted Host does not allow public access to port 8080
            pass
        
        disable_ports_commands += ["sudo ufw enable"]  # Enable UFW rules

        for cmd in firewall_commands + disable_ports_commands:
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            print(f"Executing on {instance_name}: {cmd}")
            print(stdout.read().decode())
            print(stderr.read().decode())

        print(f"Instance {instance_name} secured successfully!")
    except Exception as e:
        print(f"Error securing instance {instance_name}: {e}")


def configure_security(instances, key_pair_path):
    """
    Configure security measures for Trusted Host and Gatekeeper.
    """
    for instance_name in ['trusted-host', 'gatekeeper']:
        try:
            if instance_name not in instances:
                print(f"{instance_name} not found, skipping security configuration.")
                continue

            # SSH connection to the instance
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            private_key = paramiko.RSAKey.from_private_key_file(key_pair_path)
            
            ssh.connect(
                hostname=instances[instance_name]['public_ip'],
                username='ubuntu',
                pkey=private_key
            )

            # Secure the instance
            secure_instance(ssh, instance_name, instances.get('gatekeeper', {}).get('public_ip'))
            
            ssh.close()
        except Exception as e:
            print(f"Error configuring security for {instance_name}: {e}")

def main():
    cluster_setup = MySQLClusterSetup()
    instances = cluster_setup.setup_mysql_cluster()

    if instances:
        # Secure Trusted Host and Gatekeeper
        configure_security(instances, cluster_setup.key_pair_path)

if __name__ == '__main__':
    main()