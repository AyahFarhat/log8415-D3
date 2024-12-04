import time
import asyncio
from create_instances import MySQLClusterSetup
from deploy_code import deploy_code_on_instances
from benchmark_requests import benchmark_all

def main():
    print("Starting MySQL cluster setup...")
    cluster_setup = MySQLClusterSetup()
    cluster_setup.setup_mysql_cluster()
    print("MySQL cluster setup complete. Waiting for 30 seconds...")
    time.sleep(30)
    
    print("Deploying code on instances...")
    deploy_code_on_instances()
    print("Code deployment complete. Waiting for 10 seconds...")
    time.sleep(10)
    
    print("Starting benchmark...")
    asyncio.run(benchmark_all())
    print("Benchmark complete.")

if __name__ == "__main__":
    main()
