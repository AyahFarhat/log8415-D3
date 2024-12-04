from fastapi import FastAPI, HTTPException, Request
import httpx
import logging
import re

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
                return instance.private_ip_address or instance.public_ip_address
            else:
                print(f"Instance {instance_name} is not in running state.")
                return None
        except Exception as e:
            print(f"Error fetching IP for instance {instance_name}: {e}")
            return None

# Initialize instance discovery
discovery = InstanceDiscovery()

# Retrieve the Trusted Host IP
TRUSTED_HOST_IP = discovery.get_instance_ip_by_name('trusted-host')

app = FastAPI()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Gatekeeper")

TRUSTED_HOST_URL = f"http://{TRUSTED_HOST_IP}:8080"
logger.info(f"TRUSTED_HOST_URL {TRUSTED_HOST_URL}")


@app.post("/process")
async def process_request(request: Request):
    """
    Process incoming requests, validate, and forward to the Trusted Host.
    """
    try:
        # Parse incoming JSON
        data = await request.json()
        
        target_url = f"{TRUSTED_HOST_URL}/process"
        logger.info(f"Forwarding POST request to {target_url}")

        # Forward the request to the Trusted Host
        async with httpx.AsyncClient() as client:
            trusted_response = await client.post(target_url, json=data)
        
        # Return the response from the Trusted Host
        return trusted_response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy gatekeeper"}


@app.put("/set_mode/{mode}")
async def validate_set_mode(mode: str):
    """Validate and forward mode setting requests to the Trusted Host."""
    if mode not in ["direct", "random", "customized"]:
        raise HTTPException(status_code=400, detail="Invalid routing mode")
    try:        
        target_url = f"{TRUSTED_HOST_URL}/set_mode/{mode}"
        logger.info(f"Forwarding PUT request to {target_url}")
        
        async with httpx.AsyncClient() as client:
            response = await client.put(target_url)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error forwarding set_mode request to trusted_host: {e}")
