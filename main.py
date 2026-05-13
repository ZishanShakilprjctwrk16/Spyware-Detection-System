import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from datetime import datetime
import subprocess
import threading
import shutil


BASE_DIR = Path(__file__).parent
REPORT_DIR = BASE_DIR / "reports"

BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
BUTTON_COLOR = "#2563eb"
BUTTON_HOVER = "#1d4ed8"
TEXT_COLOR = "#f8fafc"
SUBTEXT_COLOR = "#cbd5e1"
OUTPUT_BG = "#020617"
OUTPUT_TEXT = "#e5e7eb"


def find_tool(tool_name, extra_paths=None):
    path = shutil.which(tool_name)
    if path:
        return path

    if extra_paths:
        for p in extra_paths:
            if Path(p).exists():
                return str(Path(p))

    return None


NMAP_PATH = find_tool(
    "nmap",
    [
        BASE_DIR / "Security Tools" / "NMAP" / "nmap.exe",
        BASE_DIR / "Security Tools" / "NMAP" / "nmap.EXE",
    ],
)

OSQUERY_PATH = find_tool(
    "osqueryi",
    [
        BASE_DIR / "Security Tools" / "OSQUERY" / "osqueryi.exe",
        r"C:\Program Files\osquery\osqueryi.exe",
    ],
)

WIRESHARK_PATH = find_tool(
    "Wireshark.exe",
    [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
    ],
)


def run_command(command, timeout=120):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        if result.stdout:
            return result.stdout
        if result.stderr:
            return result.stderr
        return "Command executed successfully, but no output was returned."

    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except Exception as error:
        return f"Error: {error}"


def run_in_thread(function):
    thread = threading.Thread(target=function)
    thread.daemon = True
    thread.start()


def clear_output(title):
    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"{title}\n", "title")
    output_box.insert(tk.END, "=" * 90 + "\n\n")
    output_box.config(state="disabled")


def append_output(text):
    output_box.config(state="normal")
    output_box.insert(tk.END, str(text) + "\n")
    output_box.see(tk.END)
    output_box.config(state="disabled")


def set_status(message):
    status_label.config(text=f"Status: {message}")


def styled_button(parent, text, command, row, column):
    button = tk.Button(
        parent,
        text=text,
        command=command,
        width=26,
        height=2,
        bg=BUTTON_COLOR,
        fg="white",
        activebackground=BUTTON_HOVER,
        activeforeground="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10, "bold")
    )
    button.grid(row=row, column=column, padx=10, pady=10)

    button.bind("<Enter>", lambda e: button.config(bg=BUTTON_HOVER))
    button.bind("<Leave>", lambda e: button.config(bg=BUTTON_COLOR))

    return button


def show_tool_status():
    clear_output("SECURITY TOOL STATUS")
    set_status("Checking installed tools")

    append_output("Nmap:")
    append_output(NMAP_PATH if NMAP_PATH else "Not found")

    append_output("\nOSQuery:")
    append_output(OSQUERY_PATH if OSQUERY_PATH else "Not found")

    append_output("\nWireshark:")
    append_output(WIRESHARK_PATH if WIRESHARK_PATH else "Not found")

    append_output("\nStartup Registry Check:")
    append_output("Available using Windows Registry command")

    append_output("\nReport Generator:")
    append_output("Available")

    set_status("Tool status checked")


def nmap_scan():
    def task():
        clear_output("NMAP NETWORK MONITORING")
        set_status("Running Nmap scan")

        if not NMAP_PATH:
            append_output("Nmap was not found.")
            append_output("Install Nmap or place it inside Security Tools\\NMAP.")
            set_status("Nmap not found")
            return

        append_output("[Tool Found]")
        append_output(NMAP_PATH)

        append_output("\n[Checking Nmap Version]")
        append_output(run_command([NMAP_PATH, "--version"], timeout=30))

        append_output("\n[Running Localhost Service Scan]")
        append_output("Command: nmap -sV 127.0.0.1\n")

        result = run_command([NMAP_PATH, "-sV", "127.0.0.1"], timeout=180)
        append_output(result)

        append_output("\n[Security Meaning]")
        append_output(
            "Nmap checks open ports and services. Unknown open services may indicate "
            "suspicious remote access, backdoor activity, or spyware communication."
        )

        set_status("Nmap scan completed")

    run_in_thread(task)


def osquery_scan():
    def task():
        clear_output("OSQUERY SYSTEM MONITORING")
        set_status("Running OSQuery scan")

        if not OSQUERY_PATH:
            append_output("OSQuery was not found.")
            append_output("Place osqueryi.exe inside Security Tools\\OSQUERY.")
            set_status("OSQuery not found")
            return

        append_output("[Tool Found]")
        append_output(OSQUERY_PATH)

        append_output("\n[Checking OSQuery Version]")
        append_output(run_command([OSQUERY_PATH, "--version"], timeout=30))

        query = "select pid, name, path from processes limit 50;"

        append_output("\n[Running Process Query]")
        append_output(query + "\n")

        result = run_command([OSQUERY_PATH, "--json", query], timeout=60)
        append_output(result)

        append_output("\n[Suspicious Process Analysis]")
        append_output("-" * 90)

        suspicious_keywords = [
            "temp",
            "appdata",
            "downloads",
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "unknown"
        ]

        lower_result = result.lower()
        found = False

        for keyword in suspicious_keywords:
            if keyword in lower_result:
                found = True
                append_output(f"[WARNING] Suspicious keyword found: {keyword}")

        if not found:
            append_output("No suspicious process keyword detected.")

        append_output("\n[Security Meaning]")
        append_output(
            "Spyware often hides as a background process or runs from suspicious "
            "locations such as Temp, AppData, or Downloads."
        )

        set_status("OSQuery scan completed")

    run_in_thread(task)


def open_wireshark():
    clear_output("WIRESHARK NETWORK TRAFFIC ANALYSIS")
    set_status("Opening Wireshark")

    if not WIRESHARK_PATH:
        append_output("Wireshark was not found.")
        append_output("Install Wireshark or check this path:")
        append_output(r"C:\Program Files\Wireshark\Wireshark.exe")
        set_status("Wireshark not found")
        return

    append_output("[Tool Found]")
    append_output(WIRESHARK_PATH)

    try:
        subprocess.Popen([WIRESHARK_PATH])

        append_output("\nWireshark opened successfully.")
        append_output("\nDemo Steps:")
        append_output("1. Double-click Wi-Fi or Ethernet.")
        append_output("2. Open any website.")
        append_output("3. Show captured packets.")
        append_output("4. Stop capture using the red stop button.")

        append_output("\n[Security Meaning]")
        append_output(
            "Wireshark captures live network packets. Spyware may communicate "
            "with remote servers, so traffic analysis helps investigate suspicious "
            "network communication."
        )

        set_status("Wireshark opened")

    except Exception as error:
        append_output(f"Error opening Wireshark: {error}")
        set_status("Wireshark launch failed")


def startup_check():
    def task():
        clear_output("WINDOWS STARTUP PROGRAM CHECK")
        set_status("Checking startup programs")

        append_output("[Current User Startup Programs]")
        append_output("-" * 90)

        command1 = [
            "reg",
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ]
        append_output(run_command(command1, timeout=30))

        append_output("\n[All Users Startup Programs]")
        append_output("-" * 90)

        command2 = [
            "reg",
            "query",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ]
        append_output(run_command(command2, timeout=30))

        append_output("\n[Security Meaning]")
        append_output(
            "Spyware often creates startup entries so it can run automatically "
            "whenever Windows starts."
        )

        set_status("Startup check completed")

    run_in_thread(task)


def generate_report():
    content = output_box.get("1.0", tk.END).strip()

    if not content:
        messagebox.showwarning("Warning", "No output available to save.")
        return

    REPORT_DIR.mkdir(exist_ok=True)

    filename = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write("Integrated Spyware Detection and Investigation System\n")
        file.write("Windows 11 Security Tools Prototype Report\n")
        file.write("=" * 90 + "\n")
        file.write(f"Generated Time: {datetime.now()}\n")
        file.write("=" * 90 + "\n\n")
        file.write(content)

    set_status("Report generated")
    messagebox.showinfo("Report Saved", f"Report saved successfully:\n{filename}")


root = tk.Tk()
root.title("Integrated Spyware Detection and Investigation System")
root.geometry("1150x760")
root.configure(bg=BG_COLOR)

header_frame = tk.Frame(root, bg=BG_COLOR)
header_frame.pack(fill="x", pady=(20, 10))

title_label = tk.Label(
    header_frame,
    text="Integrated Spyware Detection and Investigation System",
    font=("Segoe UI", 22, "bold"),
    bg=BG_COLOR,
    fg=TEXT_COLOR
)
title_label.pack()

subtitle_label = tk.Label(
    header_frame,
    text="Windows 11 Security Tools Integration Prototype",
    font=("Segoe UI", 12),
    bg=BG_COLOR,
    fg=SUBTEXT_COLOR
)
subtitle_label.pack(pady=(6, 0))

main_card = tk.Frame(root, bg=CARD_COLOR)
main_card.pack(fill="x", padx=35, pady=15)

button_frame = tk.Frame(main_card, bg=CARD_COLOR)
button_frame.pack(pady=18)

styled_button(button_frame, "Check Tool Status", show_tool_status, 0, 0)
styled_button(button_frame, "Nmap Network Scan", nmap_scan, 0, 1)
styled_button(button_frame, "OSQuery System Scan", osquery_scan, 0, 2)
styled_button(button_frame, "Open Wireshark", open_wireshark, 1, 0)
styled_button(button_frame, "Startup Program Check", startup_check, 1, 1)
styled_button(button_frame, "Generate Report", generate_report, 1, 2)

output_frame = tk.Frame(root, bg=BG_COLOR)
output_frame.pack(expand=True, fill="both", padx=35, pady=(5, 15))

output_box = tk.Text(
    output_frame,
    wrap=tk.WORD,
    font=("Consolas", 10),
    bg=OUTPUT_BG,
    fg=OUTPUT_TEXT,
    insertbackground="white",
    relief="flat",
    padx=14,
    pady=14
)
output_box.pack(side="left", expand=True, fill="both")

scrollbar = tk.Scrollbar(output_frame, command=output_box.yview)
scrollbar.pack(side="right", fill="y")
output_box.config(yscrollcommand=scrollbar.set)

output_box.tag_config("title", foreground="#38bdf8", font=("Consolas", 12, "bold"))

status_label = tk.Label(
    root,
    text="Status: System ready",
    font=("Segoe UI", 10),
    bg=BG_COLOR,
    fg=SUBTEXT_COLOR,
    anchor="w"
)
status_label.pack(fill="x", padx=35, pady=(0, 10))

clear_output("SYSTEM READY")
append_output("Integrated Spyware Detection and Investigation System initialized.")
append_output("\nAvailable Modules:")
append_output("- Nmap Network Scan")
append_output("- OSQuery System Monitoring")
append_output("- Wireshark Traffic Analysis")
append_output("- Windows Startup Persistence Check")
append_output("- Report Generation")
append_output("\nSelect a module to begin investigation.")

root.mainloop()