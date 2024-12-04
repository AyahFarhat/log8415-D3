import time
import asyncio
from create_instances import MySQLClusterSetup
from deploy_code import deploy_code_on_instances
from benchmark_requests import benchmark_all

def main():
    cluster_setup = MySQLClusterSetup()
    cluster_setup.setup_mysql_cluster()
    time.sleep(30)
    deploy_code_on_instances()
    time.sleep(10)
    asyncio.run(benchmark_all())

if __name__ == "__main__":
    main()