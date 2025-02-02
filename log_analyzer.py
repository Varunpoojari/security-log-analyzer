import pandas as pd
from datetime import datetime
import json

class SecurityLogAnalyzer:
    """
    A basic security log analyzer that can detect simple anomalies in log files.
    This class will grow more sophisticated as we add more features.
    """
    
    def __init__(self):
        """Initialize the analyzer with basic settings"""
        self.log_data = None
        self.anomalies = []
    
    def load_log_file(self, file_path):
        """
        Load a log file for analysis
        Args:
            file_path (str): Path to the log file
        """
        try:
            # We'll start with JSON format logs for simplicity
            with open(file_path, 'r') as file:
                self.log_data = pd.DataFrame([json.loads(line) for line in file])
            return True
        except Exception as e:
            print(f"Error loading log file: {e}")
            return False
    
    def detect_basic_anomalies(self):
        """
        Detect basic anomalies in the logs:
        - Failed login attempts
        - Unusual access times
        - High frequency of events from same IP
        """
        if self.log_data is None:
            return "No log data loaded"
        
        # Look for failed login attempts
        failed_logins = self.log_data[
            self.log_data['event_type'] == 'login_attempt'
        ][
            self.log_data['status'] == 'failed'
        ]
        
        # Group by IP address to find suspicious activity
        ip_counts = failed_logins['source_ip'].value_counts()
        suspicious_ips = ip_counts[ip_counts > 5].index.tolist()
        
        # Record findings
        for ip in suspicious_ips:
            self.anomalies.append({
                'type': 'suspicious_login_attempts',
                'ip_address': ip,
                'count': ip_counts[ip],
                'timestamp': datetime.now().isoformat()
            })
        
        return self.anomalies

if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer()
    print("Starting security log analysis...")
    
    # Load and analyze the log file
    if analyzer.load_log_file("security_logs.json"):
        print("Log file loaded successfully!")
        anomalies = analyzer.detect_basic_anomalies()
        
        if anomalies:
            print("\nDetected Anomalies:")
            for anomaly in anomalies:
                print(f"\nSuspicious activity from IP: {anomaly['ip_address']}")
                print(f"Number of failed attempts: {anomaly['count']}")
                print(f"Detected at: {anomaly['timestamp']}")
        else:
            print("\nNo anomalies detected")