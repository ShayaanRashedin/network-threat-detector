from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    "owner": "shayaan",
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

with DAG(
    dag_id="network_threat_detector_pipeline",
    default_args=default_args,
    description="Run the Python Network Threat Detector pipeline",
    start_date=datetime(2026, 1, 1),
    schedule="@daily",
    catchup=False,
    tags=["cybersecurity", "network-detection", "python"],
) as dag:
    
    run_detector = BashOperator(
        task_id="run_network_threat_detector",
        bash_command=(
            "cd /opt/airflow/network-threat-detector && "
            "python main.py --file sample_logs.csv --format custom"
        ),
    )