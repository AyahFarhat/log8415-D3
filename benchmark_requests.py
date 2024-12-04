import asyncio
import time
import boto3
import httpx


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
            filters = [
                {'Name': 'tag:Name', 'Values': [instance_name]},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
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


async def send_requests(gatekeeper_url, mode, num_requests, read_query, write_query):
    """
    Send `num_requests` read and write requests to the Gatekeeper and measure performance.
    """
    # Set the mode on the Gatekeeper
    async with httpx.AsyncClient() as client:
        response = await client.put(f"{gatekeeper_url}/set_mode/{mode}")
        if response.status_code != 200:
            raise Exception(f"Failed to set mode to {mode}: {response.text}")

    print(f"Mode set to {mode}. Sending requests...")

    # Send read requests
    read_times = []
    async with httpx.AsyncClient() as client:
        for _ in range(num_requests):
            start_time = time.perf_counter()
            response = await client.post(f"{gatekeeper_url}/process", json=read_query)
            end_time = time.perf_counter()
            read_times.append(end_time - start_time)
            if response.status_code != 200:
                print(f"Read request failed: {response.text}")

    # Send write requests
    write_times = []
    async with httpx.AsyncClient() as client:
        for _ in range(num_requests):
            start_time = time.perf_counter()
            response = await client.post(f"{gatekeeper_url}/process", json=write_query)
            end_time = time.perf_counter()
            write_times.append(end_time - start_time)
            if response.status_code != 200:
                print(f"Write request failed: {response.text}")

    # Calculate and return metrics
    avg_read_time = sum(read_times) / len(read_times)
    avg_write_time = sum(write_times) / len(write_times)

    return {
        "mode": mode,
        "avg_read_time": avg_read_time,
        "avg_write_time": avg_write_time,
        "total_read_time": sum(read_times),
        "total_write_time": sum(write_times),
    }


async def benchmark(gatekeeper_url, num_requests, read_query, write_query):
    """
    Benchmark the three modes and print the results.
    """
    results = []

    for mode in ["direct", "random", "customized"]:
        print(f"Benchmarking mode: {mode}")
        result = await send_requests(gatekeeper_url, mode, num_requests, read_query, write_query)
        results.append(result)

    print("\nBenchmark Results:")
    for result in results:
        print(f"Mode: {result['mode']}")
        print(f"  Avg Read Time: {result['avg_read_time']:.6f} seconds")
        print(f"  Avg Write Time: {result['avg_write_time']:.6f} seconds")
        print(f"  Total Read Time: {result['total_read_time']:.2f} seconds")
        print(f"  Total Write Time: {result['total_write_time']:.2f} seconds")
        print("-" * 50)


async def benchmark_all():
    discovery = InstanceDiscovery()
    gatekeeper_server_ip = discovery.get_instance_ip_by_name('gatekeeper')
    if not gatekeeper_server_ip:
        print("Could not retrieve Gatekeeper server IP. Exiting.")
        return

    gatekeeper_url = f"http://{gatekeeper_server_ip}:8080"
    read_query = {"query": "SELECT * FROM sakila.actor LIMIT 10"}
    write_query = {"query": "INSERT INTO sakila.actor (first_name, last_name) VALUES ('Test', 'User')"}
    num_requests = 1000

    # Call the benchmark coroutine directly (no nested asyncio.run)
    await benchmark(gatekeeper_url, num_requests, read_query, write_query)



if __name__ == "__main__":
    benchmark_all()
