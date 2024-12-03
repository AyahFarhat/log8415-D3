import logging
import boto3
from fastapi import FastAPI, Request, HTTPException
import mysql.connector
import random
import subprocess
from typing import List

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
                return instance.private_ip_address or instance.public_ip_address
            else:
                print(f"Instance {instance_name} is not in running state.")
                return None
        except Exception as e:
            print(f"Error fetching IP for instance {instance_name}: {e}")
            return None
        
discovery = InstanceDiscovery()

# Retrieve the Proxy Server IP
MANAGER_DB = discovery.get_instance_ip_by_name('mysql-manager')


WORKER1_DB = discovery.get_instance_ip_by_name('mysql-worker-1')


WORKER2_DB = discovery.get_instance_ip_by_name('mysql-worker-2')

        
app = FastAPI()

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Proxy Server")

# MySQL Manager node configuration
manager_db_config = {
    'host': MANAGER_DB,  
    'user': 'user',
    'password': 'password',
    'database': 'sakila'
}

# MySQL Worker nodes configuration
worker_db_configs = [
    {'host': WORKER1_DB, 'user': 'user', 'password': 'password', 'database': 'sakila'},
    {'host': WORKER2_DB, 'user': 'user', 'password': 'password', 'database': 'sakila'}
]

# Current routing mode (can be 'direct', 'random', or 'customized')
routing_mode = "direct"  # Set the mode here

def get_mysql_connection(db_config):
    """Connect to a MySQL database with the provided configuration."""
    try:
        return mysql.connector.connect(**db_config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

def ping_server(host: str) -> float:
    """Ping a host and return the average response time in ms."""
    try:
        result = subprocess.run(['ping', '-c', '1', host], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        # Extract the ping time from the output
        time_str = output.split("time=")[-1].split(" ")[0]
        return float(time_str)
    except Exception as e:
        print(f"Failed to ping {host}: {e}")
        return float('inf')  # If ping fails, return an infinite time

def get_least_ping_worker() -> dict:
    """Find and return the Worker node with the least ping time."""
    ping_times = [(worker, ping_server(worker['host'])) for worker in worker_db_configs]
    # Sort by ping time and return the worker with the lowest time
    best_worker = min(ping_times, key=lambda x: x[1])[0]
    return best_worker

@app.get("/read")
async def read_data(request: Request):
    try:
        data = await request.json()
        query = data.get("query")
        
        if not query:
            raise HTTPException(status_code=400, detail="Query is required.")
        logger.info(f"QUERY {   query}")
        
        if routing_mode == "direct":
            # Directly use the manager node for read operations
            db_config = manager_db_config
        elif routing_mode == "random":
            # Randomly select a Worker node for read operations
            db_config = random.choice(worker_db_configs)
        elif routing_mode == "customized":
            # Use the Worker node with the least ping time
            db_config = get_least_ping_worker()
        else:
            raise HTTPException(status_code=400, detail="Invalid routing mode")

        conn = get_mysql_connection(db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in read operation: {str(e)}")

@app.post("/write")
async def write_data(request: Request):
    try:
            
        data = await request.json()
        query = data.get("query")
        if not query:
            raise HTTPException(status_code=400, detail="Query is required.")
        logger.info(f"QUERY {   query}")
        
        # Write operations always go to the Manager node
        conn = get_mysql_connection(manager_db_config)
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Write operation completed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in write operation: {str(e)}")

@app.put("/set_mode/{mode}")
async def set_routing_mode(mode: str):
    """Set the routing mode: 'direct', 'random', or 'customized'."""
    global routing_mode
    if mode not in ["direct", "random", "customized"]:
        raise HTTPException(status_code=400, detail="Invalid routing mode")
    routing_mode = mode
    return {"status": "Routing mode updated", "mode": routing_mode}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy proxy"}
