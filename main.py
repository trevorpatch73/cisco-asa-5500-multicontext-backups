import re
import os
import csv
from netmiko import ConnectHandler

# GLOBAL VARIABLES
FIREWALL_USERNAME = os.environ.get("FIREWALL_USERNAME")
FIREWALL_PASSWORD = os.environ.get("FIREWALL_PASSWORD")
BACKUP_SERVER_USERNAME = os.environ.get("BACKUP_SERVER_USERNAME")
BACKUP_SERVER_PASSWORD = os.environ.get("BACKUP_SERVER_PASSWORD")

# GLOBAL GAURDRAILS
if not FIREWALL_USERNAME:
    print("FIREWALL_USERNAME environment variable not set!")
    exit(1)
if not FIREWALL_PASSWORD:
    print("FIREWALL_PASSWORD environment variable not set!")
    exit(1)
if not BACKUP_SERVER_USERNAME:
    print("BACKUP_SERVER_USERNAME environment variable not set!")
    exit(1)
if not BACKUP_SERVER_PASSWORD:
    print("BACKUP_SERVER_PASSWORD environment variable not set!")
    exit(1)

# INVOKABLE FUNCTIONS
def abort(message):
    print(f"ABORT: {message}")
    exit(1)

def connect_firewall(FIREWALL_USERNAME, FIREWALL_PASSWORD, MANAGEMENT_IP):
    device = {
        'device_type': 'cisco_asa',
        'ip': MANAGEMENT_IP,
        'username': FIREWALL_USERNAME,
        'password': FIREWALL_PASSWORD,
        'secret': FIREWALL_PASSWORD,
    }

    try:
        connection = ConnectHandler(**device)
        connection.enable()
        return connection
    except Exception as e:
        abort(f"Failed to connect to the firewall: {str(e)}")

def changeto_system(connection, FIREWALL_NAME, EXPECTED_PROMPT):
    # Switch to the proper context to perform backups
    connection.send_command("changeto system", expect_string=EXPECTED_PROMPT)

    # Local Function Guardrails
    if connection.find_prompt() != EXPECTED_PROMPT:
        abort(f"Failed to change to system context. Expected prompt: {EXPECTED_PROMPT}")

def get_contexts(connection, FIREWALL_NAME):
    # Send command to get printout of contexts
    output = connection.send_command("show context")

    # Divide printout into rows for analysis
    lines = output.splitlines()

    # Define a list to store context names
    CONTEXT_NAMES = []

    # Analyze output line by line 
    for line in lines:
        match = re.search(r"^\s*(\S+)\s+", line)
        if match:
            context_name = match.group(1).strip()
            # Regex tested to match the firewall prompt line & printout headers;
            # Attempting to parse that out here, and not add to list
            if context_name != FIREWALL_NAME and context_name != "Context Name":
                CONTEXT_NAMES.append(context_name)

    return CONTEXT_NAMES

def run_backups(connection, CONTEXT_NAMES, BACKUP_SERVER_IP, BACKUP_SERVER_PATH, BACKUP_SERVER_USERNAME, BACKUP_SERVER_PASSWORD):
    for CONTEXT in CONTEXT_NAMES:
        # Send command to execute backup to server for context
        output = connection.send_command(f"backup /noconfig context {CONTEXT} location scp://{BACKUP_SERVER_USERNAME}:{BACKUP_SERVER_PASSWORD}@{BACKUP_SERVER_IP}/{BACKUP_SERVER_PATH}/")

        # Local Function Guardrails
        if "error" in output.lower() or "failed" in output.lower():
            abort(f"Backup for context {CONTEXT} failed.")

def main():
    # Open the inventory file, and iterated down it
    with open('DEVICE_INVENTORY.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Map the columns of the row being iterated to variables
            FIREWALL_NAME = row['FIREWALL_NAME']
            MANAGEMENT_IP = row['MANAGEMENT_IP']
            BACKUP_SERVER_IP = row['BACKUP_SERVER_IP']
            BACKUP_SERVER_PATH = row['BACKUP_SERVER_PATH']
            EXPECTED_PROMPT = f"{FIREWALL_NAME}#"

            # Connect to the firewall
            connection = connect_firewall(FIREWALL_USERNAME, FIREWALL_PASSWORD, MANAGEMENT_IP)

            # Changeto System Context
            changeto_system(connection, FIREWALL_NAME, EXPECTED_PROMPT)

            # Get A List of Contexts
            CONTEXT_NAMES = get_contexts(connection, FIREWALL_NAME)

            # Issue Backup Commands Per Context From System
            run_backups(connection, CONTEXT_NAMES, BACKUP_SERVER_IP, BACKUP_SERVER_PATH, BACKUP_SERVER_USERNAME, BACKUP_SERVER_PASSWORD)

            # Disconnect from the firewall
            connection.disconnect()

# SCRIPT ACTIONS INITIALIZATION
if __name__ == "__main__":
    main()
