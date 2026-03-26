import os
import subprocess
import sys
import time

def main():
    print("Starting Phishing URL Detection Application...")
    
    # Start backend server
    print("Starting backend server...")
    backend_cmd = 'python backend/manage.py runserver'
    backend_process = subprocess.Popen(backend_cmd, shell=True)
    
    # Wait a bit for the backend to start
    time.sleep(5)
    
    # Start frontend server
    print("Starting frontend server...")
    frontend_cmd = 'cd frontend && npm start'
    frontend_process = subprocess.Popen(frontend_cmd, shell=True)
    
    print("\nApplications should be running!")
    print("Backend: http://localhost:8000")
    print("Frontend: http://localhost:3000")
    print("\nPress Ctrl+C to stop both servers.")
    
    try:
        # Keep the script running to maintain the servers
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Stop servers on Ctrl+C
        print("\nStopping servers...")
        backend_process.terminate()
        frontend_process.terminate()
        print("Servers stopped.")

if __name__ == "__main__":
    main() 