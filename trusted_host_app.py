import logging
from fastapi import FastAPI, HTTPException, Request
import httpx

import boto3

class InstanceDiscovery:
    def __init__(self, region='us-east-1'):
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

discovery = InstanceDiscovery()

PROXY_SERVER_IP = discovery.get_instance_ip_by_name('mysql-proxy')

app = FastAPI()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("truested_host")

PROXY_SERVER_URL = f"http://{PROXY_SERVER_IP}:8080"
logger.info(f"PROXY_SERVER_URL {PROXY_SERVER_URL}")


@app.post("/process")
async def process_request(request: Request):
    """
    Process requests from the Gatekeeper and forward them to the Proxy.
    """
    try:
        data = await request.json()
        
        if "query" not in data:
            raise HTTPException(status_code=400, detail="Invalid request: 'query' field is required")

        query = data["query"].strip()

        # Determine whether the query is a READ or WRITE operation
        query_upper = query.upper()
        if query_upper.startswith("SELECT"):
            operation_type = "read"
            method = "GET"
        elif query_upper.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE")):
            operation_type = "write"
            method = "POST"
        else:
            raise HTTPException(status_code=400, detail="Unsupported query operation")

        # Forward request to the Proxy
        async with httpx.AsyncClient() as client:
            if method == "GET":
                # Forward as a GET request, include query in params
                proxy_response = await client.get(
                    f"{PROXY_SERVER_URL}/{operation_type}",
                    params={"query": query}
                )
            else:
                # Forward as a POST request
                proxy_response = await client.post(
                    f"{PROXY_SERVER_URL}/{operation_type}",
                    json={"query": query}
                )

        proxy_response.raise_for_status()

        return proxy_response.json()
    except httpx.HTTPStatusError as http_error:
        raise HTTPException(
            status_code=http_error.response.status_code,
            detail=f"Proxy error: {http_error.response.text}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")



@app.put("/set_mode/{mode}")
async def route_set_mode(mode: str):
    """Route mode setting requests to the Proxy Server."""
    if mode not in ["direct", "random", "customized"]:
        raise HTTPException(status_code=400, detail="Invalid routing mode")
    try:
        
        target_url = f"{PROXY_SERVER_URL}/set_mode/{mode}"
        logger.info(f"Forwarding PUT request to {target_url}")
        
        async with httpx.AsyncClient() as client:
            response = await client.put(f"{PROXY_SERVER_URL}/set_mode/{mode}")
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error forwarding set_mode request to proxy: {e}")
    
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy trusted host"}