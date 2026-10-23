import sys
import os
import subprocess

# Ensure console handles UTF-8 on Windows without UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Check if running under Streamlit
try:
    import streamlit.web.cli as stcli
    from streamlit import runtime
    is_streamlit = runtime.exists()
except ImportError:
    is_streamlit = False

if is_streamlit:
    # If launched via: streamlit run "port scanner.py"
    import runpy
    app_path = os.path.join(os.path.dirname(__file__), "app.py")
    runpy.run_path(app_path, run_name="__main__")
else:
    # If launched via: python "port scanner.py"
    print("=" * 60)
    print("        🛡️  PORTSENTINEL • NETWORK PORT SCANNER  🛡️")
    print("=" * 60)
    print("\nSelect Mode:")
    print("  [1] 🌐 Launch Modern Streamlit Web UI (Recommended)")
    print("  [2] 💻 Run Fast Terminal CLI Scanner")
    
    try:
        choice = input("\nEnter choice (1 or 2, default is 1): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

    if choice in ("", "1"):
        print("\n🚀 Starting Streamlit Web UI on http://localhost:8501 ...")
        app_path = os.path.join(os.path.dirname(__file__), "app.py")
        subprocess.run([sys.executable, "-m", "streamlit", "run", app_path])
    else:
        import socket

        target = input("\nEnter Target IP or Domain: ").strip()
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"\n[-] Error: Could not resolve hostname '{target}'.")
            sys.exit(1)

        try:
            start_port = int(input("Enter Starting Port: "))
            end_port = int(input("Enter Ending Port: "))
        except ValueError:
            print("[-] Invalid port number.")
            sys.exit(1)

        print(f"\nScanning {target} ({target_ip}) from port {start_port} to {end_port}...\n")

        try:
            for port in range(start_port, end_port + 1):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        print(f"[+] Port {port} is OPEN")
        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user.")
            sys.exit(0)

        print("\nScan Completed.")
