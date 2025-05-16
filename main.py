import argparse
import socket
import logging
import sys
import concurrent.futures

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common vulnerable ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8443, 9000, 9200, 27017]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Lightweight Open Port Scanner focused on vulnerable services.')
    parser.add_argument('target', help='Target host or IP address to scan.')
    parser.add_argument('-p', '--ports', nargs='+', type=int, help='Specify a list of ports to scan. Defaults to common vulnerable ports.', default=COMMON_PORTS)
    parser.add_argument('-t', '--threads', type=int, help='Number of threads to use for scanning (default: 10)', default=10)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging.')

    return parser.parse_args()


def is_valid_ipv4_address(address):
    """
    Checks if the provided address is a valid IPv4 address.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # inet_pton is not available on Windows XP
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


def is_valid_hostname(hostname):
    """
    Checks if the provided string is a valid hostname.  A very basic check.  More rigorous checks exist.
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def scan_port(target, port, verbose=False):
    """
    Scans a single port on the target host.

    Args:
        target (str): The target host or IP address.
        port (int): The port to scan.
        verbose (bool): Enable verbose output.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout of 1 second
        
        # Attempt to connect to the target and port
        result = sock.connect_ex((target, port))
        
        if result == 0:
            logging.info(f"Port {port} is open on {target}")
            if verbose:
                try:
                    service_name = socket.getservbyport(port)
                    logging.info(f"Service: {service_name}")
                except socket.error:
                    logging.info("Service name not found.")

            sock.close()
            return True
        else:
            if verbose:
                logging.debug(f"Port {port} is closed on {target}")
            sock.close()
            return False

    except socket.gaierror:
        logging.error(f"Could not resolve hostname for {target}")
        return False
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to execute the port scanner.
    """
    args = setup_argparse()

    target = args.target
    ports = args.ports
    threads = args.threads
    verbose = args.verbose

    # Validate target input
    if not (is_valid_ipv4_address(target) or is_valid_hostname(target)):
        logging.error("Invalid target.  Must be a valid IPv4 address or hostname.")
        sys.exit(1)
        
    # Validate ports input
    if not all(1 <= port <= 65535 for port in ports):
        logging.error("Invalid port number. Port must be between 1 and 65535.")
        sys.exit(1)
    
    # Validate threads input
    if threads <= 0:
        logging.error("Number of threads must be greater than 0.")
        sys.exit(1)
    
    logging.info(f"Starting scan on {target} with {threads} threads...")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Use a list comprehension to create a list of futures
            futures = [executor.submit(scan_port, target, port, verbose) for port in ports]

            # Wait for all futures to complete
            concurrent.futures.wait(futures)
    
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        sys.exit(1)

    logging.info("Scan complete.")


if __name__ == "__main__":
    import re
    main()