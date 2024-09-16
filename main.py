import pyodbc
import xml.etree.ElementTree as ET
import sys
import os
import datetime
import logging
import hashlib
import zipfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, filename='nessus_compare.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')

def initialize_database(db_path):
    """
    Initialize the Microsoft Access database and create tables if they do not exist.
    """
    conn_str = (
        r'DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};'
        r'DBQ={db_path};'
    ).format(db_path=db_path)

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    
    # Create Hosts table with last_scanned field
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Hosts (
            host_id AUTOINCREMENT PRIMARY KEY,
            ip_address TEXT UNIQUE,
            hostname TEXT,
            last_scanned DATETIME
        )
    ''')
    
    # Create Vulnerabilities table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Vulnerabilities (
            vuln_id AUTOINCREMENT PRIMARY KEY,
            plugin_id INTEGER,
            name TEXT,
            severity INTEGER,
            UNIQUE (plugin_id, name)
        )
    ''')
    
    # Create Findings table with currently_present and resolved_date fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Findings (
            finding_id AUTOINCREMENT PRIMARY KEY,
            host_id INTEGER,
            vuln_id INTEGER,
            first_seen DATETIME,
            last_seen DATETIME,
            currently_present BOOLEAN,
            resolved_date DATETIME,
            FOREIGN KEY (host_id) REFERENCES Hosts(host_id),
            FOREIGN KEY (vuln_id) REFERENCES Vulnerabilities(vuln_id),
            UNIQUE (host_id, vuln_id)
        )
    ''')

    # Create ProcessedScans table to store hashes of processed Nessus files
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ProcessedScans (
            scan_id AUTOINCREMENT PRIMARY KEY,
            file_hash TEXT UNIQUE,
            processed_date DATETIME
        )
    ''')

    # Create ProcessedScanDates table to store processed scanDate folders
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ProcessedScanDates (
            scan_date_id AUTOINCREMENT PRIMARY KEY,
            scan_date TEXT UNIQUE,
            processed_date DATETIME
        )
    ''')

    conn.commit()
    return conn

def compute_file_hash(file_path):
    """
    Compute SHA-256 hash of the given file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_duplicate_scan(conn, file_hash):
    """
    Check if the scan file hash already exists in the database.
    """
    cursor = conn.cursor()
    cursor.execute('SELECT scan_id FROM ProcessedScans WHERE file_hash = ?', (file_hash,))
    result = cursor.fetchone()
    return result is not None

def record_processed_scan(conn, file_hash):
    """
    Record the hash of the processed scan file in the database.
    """
    cursor = conn.cursor()
    processed_date = datetime.datetime.now()
    cursor.execute('''
        INSERT INTO ProcessedScans (file_hash, processed_date)
        VALUES (?, ?)
    ''', (file_hash, processed_date))
    conn.commit()

def is_duplicate_scan_date(conn, scan_date):
    """
    Check if the scanDate folder has already been processed.
    """
    cursor = conn.cursor()
    cursor.execute('SELECT scan_date_id FROM ProcessedScanDates WHERE scan_date = ?', (scan_date,))
    result = cursor.fetchone()
    return result is not None

def record_processed_scan_date(conn, scan_date):
    """
    Record the processed scanDate folder in the database.
    """
    cursor = conn.cursor()
    processed_date = datetime.datetime.now()
    cursor.execute('''
        INSERT INTO ProcessedScanDates (scan_date, processed_date)
        VALUES (?, ?)
    ''', (scan_date, processed_date))
    conn.commit()

def extract_zip_files(zip_file_path, extract_to):
    """
    Extract all files from a zip archive to the specified directory.
    """
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def parse_nessus_file(file_path):
    """
    Parse the Nessus XML file and extract host and vulnerability data.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    data = []
    for report_host in root.findall('.//ReportHost'):
        host_properties = report_host.find('HostProperties')
        host_ip = None
        host_name = None
        
        for tag in host_properties:
            if tag.get('name') == 'host-ip':
                host_ip = tag.text
            if tag.get('name') == 'host-fqdn':
                host_name = tag.text
        
        for report_item in report_host.findall('ReportItem'):
            plugin_id = int(report_item.get('pluginID'))
            plugin_name = report_item.get('pluginName')
            severity = int(report_item.get('severity'))
            
            data.append({
                'ip_address': host_ip,
                'hostname': host_name,
                'plugin_id': plugin_id,
                'plugin_name': plugin_name,
                'severity': severity
            })
    
    return data

def update_database(conn, data):
    """
    Update the database with new scan data and identify new and resolved findings,
    accounting for devices that may be offline.
    """
    cursor = conn.cursor()
    new_findings = []
    resolved_findings = []
    scanned_hosts = set()
    current_time = datetime.datetime.now()
    
    # Record hosts that were scanned in this run
    for item in data:
        scanned_hosts.add(item['ip_address'])
    
    # Update last_scanned timestamp for scanned hosts
    for ip_address in scanned_hosts:
        try:
            cursor.execute('''
                UPDATE Hosts SET last_scanned = ? WHERE ip_address = ?
            ''', (current_time, ip_address))
            if cursor.rowcount == 0:
                # Host not in database, insert it
                cursor.execute('''
                    INSERT INTO Hosts (ip_address, hostname, last_scanned)
                    VALUES (?, ?, ?)
                ''', (ip_address, None, current_time))
        except pyodbc.IntegrityError as e:
            logging.error(f"Error updating host {ip_address}: {e}")
            pass
    
    conn.commit()
    
    # Set currently_present = False for findings related to hosts scanned in this run
    cursor.execute('''
        UPDATE Findings SET currently_present = False
        WHERE host_id IN (
            SELECT host_id FROM Hosts WHERE last_scanned = ?
        )
    ''', (current_time,))
    conn.commit()
    
    for item in data:
        # Get or insert host
        cursor.execute('SELECT host_id FROM Hosts WHERE ip_address = ?', (item['ip_address'],))
        result = cursor.fetchone()
        if result:
            host_id = result[0]
        else:
            cursor.execute('''
                INSERT INTO Hosts (ip_address, hostname, last_scanned)
                VALUES (?, ?, ?)
            ''', (item['ip_address'], item['hostname'], current_time))
            host_id = cursor.lastrowid
        
        # Insert or ignore vulnerability
        cursor.execute('SELECT vuln_id FROM Vulnerabilities WHERE plugin_id = ? AND name = ?', (item['plugin_id'], item['plugin_name']))
        result = cursor.fetchone()
        if result:
            vuln_id = result[0]
        else:
            cursor.execute('''
                INSERT INTO Vulnerabilities (plugin_id, name, severity)
                VALUES (?, ?, ?)
            ''', (item['plugin_id'], item['plugin_name'], item['severity']))
            vuln_id = cursor.lastrowid
        
        # Check if finding already exists
        cursor.execute('''
            SELECT finding_id FROM Findings WHERE host_id = ? AND vuln_id = ?
        ''', (host_id, vuln_id))
        result = cursor.fetchone()
        
        if result:
            # Update last_seen timestamp and set currently_present to True
            cursor.execute('''
                UPDATE Findings SET last_seen = ?, currently_present = True WHERE finding_id = ?
            ''', (current_time, result[0]))
        else:
            # New finding
            cursor.execute('''
                INSERT INTO Findings (host_id, vuln_id, first_seen, last_seen, currently_present)
                VALUES (?, ?, ?, ?, True)
            ''', (host_id, vuln_id, current_time, current_time))
            new_findings.append({
                'ip_address': item['ip_address'],
                'hostname': item['hostname'],
                'plugin_id': item['plugin_id'],
                'plugin_name': item['plugin_name'],
                'severity': item['severity']
            })
        conn.commit()
    
    # Identify resolved vulnerabilities for hosts that were scanned in this run
    cursor.execute('''
        SELECT f.finding_id, f.host_id, f.vuln_id
        FROM Findings f
        INNER JOIN Hosts h ON f.host_id = h.host_id
        WHERE f.currently_present = False
        AND f.resolved_date IS NULL
        AND h.last_scanned = ?
    ''', (current_time,))
    resolved = cursor.fetchall()

    for finding_id, host_id, vuln_id in resolved:
        resolved_date = current_time
        cursor.execute('''
            UPDATE Findings SET resolved_date = ? WHERE finding_id = ?
        ''', (resolved_date, finding_id))
        # Get host and vulnerability details for reporting
        cursor.execute('SELECT ip_address FROM Hosts WHERE host_id = ?', (host_id,))
        ip_address = cursor.fetchone()[0]
        cursor.execute('SELECT name, plugin_id, severity FROM Vulnerabilities WHERE vuln_id = ?', (vuln_id,))
        vuln = cursor.fetchone()
        resolved_findings.append({
            'ip_address': ip_address,
            'plugin_id': vuln.plugin_id,
            'plugin_name': vuln.name,
            'severity': vuln.severity
        })
    conn.commit()
    return new_findings, resolved_findings

def generate_report(new_findings, resolved_findings, report_path):
    """
    Generate a report of new and resolved findings.
    """
    with open(report_path, 'w') as report_file:
        if new_findings:
            report_file.write("New Vulnerabilities Discovered:\n")
            report_file.write("-" * 50 + "\n")
            for finding in new_findings:
                report_file.write(f"Host IP: {finding['ip_address']}\n")
                report_file.write(f"Hostname: {finding['hostname']}\n")
                report_file.write(f"Plugin ID: {finding['plugin_id']}\n")
                report_file.write(f"Plugin Name: {finding['plugin_name']}\n")
                report_file.write(f"Severity: {finding['severity']}\n")
                report_file.write("-" * 50 + "\n")
        else:
            report_file.write("No New Vulnerabilities Found.\n")
            report_file.write("-" * 50 + "\n")

        if resolved_findings:
            report_file.write("Resolved Vulnerabilities:\n")
            report_file.write("-" * 50 + "\n")
            for finding in resolved_findings:
                report_file.write(f"Host IP: {finding['ip_address']}\n")
                report_file.write(f"Plugin ID: {finding['plugin_id']}\n")
                report_file.write(f"Plugin Name: {finding['plugin_name']}\n")
                report_file.write(f"Severity: {finding['severity']}\n")
                report_file.write("-" * 50 + "\n")
        else:
            report_file.write("No Resolved Vulnerabilities.\n")
            report_file.write("-" * 50 + "\n")
    logging.info(f"Report generated at {report_path}")

def process_nessus_files_in_directory(directory, conn, report_path):
    """
    Process all .nessus files in the given directory.
    """
    new_findings_total = []
    resolved_findings_total = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.nessus'):
                nessus_file_path = os.path.join(root, file)
                logging.info(f"Processing Nessus file: {nessus_file_path}")

                file_hash = compute_file_hash(nessus_file_path)

                if is_duplicate_scan(conn, file_hash):
                    logging.info(f"The scan file {nessus_file_path} has already been processed. Skipping.")
                    continue

                scan_data = parse_nessus_file(nessus_file_path)
                new_findings, resolved_findings = update_database(conn, scan_data)
                new_findings_total.extend(new_findings)
                resolved_findings_total.extend(resolved_findings)

                # Record the processed scan hash after successful processing
                record_processed_scan(conn, file_hash)

    # Generate a consolidated report
    generate_report(new_findings_total, resolved_findings_total, report_path)

def main(dropbox_directory, db_path, report_path):
    """
    Main function to orchestrate the processing of scans in the dropbox directory.
    """
    try:
        logging.info("Initializing database.")
        conn = initialize_database(db_path)

        # Traverse the dropbox directory
        for system_name in os.listdir(dropbox_directory):
            system_path = os.path.join(dropbox_directory, system_name)
            if not os.path.isdir(system_path):
                continue

            for scan_date in os.listdir(system_path):
                scan_date_path = os.path.join(system_path, scan_date)
                if not os.path.isdir(scan_date_path):
                    continue

                logging.info(f"Processing scanDate folder: {scan_date}")

                if is_duplicate_scan_date(conn, scan_date):
                    logging.info(f"The scanDate folder {scan_date} has already been processed. Skipping.")
                    continue

                # Create a temporary directory for extraction
                temp_extract_dir = os.path.join(scan_date_path, 'extracted')
                os.makedirs(temp_extract_dir, exist_ok=True)

                try:
                    # Extract and process all scan.zip files
                    for item in os.listdir(scan_date_path):
                        if item.endswith('.zip'):
                            zip_file_path = os.path.join(scan_date_path, item)
                            logging.info(f"Extracting {zip_file_path}")
                            extract_zip_files(zip_file_path, temp_extract_dir)

                    # Process all .nessus files in the extracted directory
                    process_nessus_files_in_directory(temp_extract_dir, conn, report_path)

                    # Record the processed scanDate folder
                    record_processed_scan_date(conn, scan_date)

                except Exception as e:
                    logging.error(f"An error occurred while processing {scan_date}: {e}")
                finally:
                    # Clean up the temporary extraction directory
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)

        conn.close()
        logging.info("All scans processed successfully.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python nessus_compare.py <dropbox_directory> <database_path> <report_path>")
        sys.exit(1)

    dropbox_directory = sys.argv[1]
    db_path = sys.argv[2]
    report_path = sys.argv[3]

    if not os.path.exists(dropbox_directory):
        print(f"Dropbox directory {dropbox_directory} does not exist.")
        sys.exit(1)

    main(dropbox_directory, db_path, report_path)
