import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
from tkinter import ttk
import re
import requests
import threading

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Log Analyzer")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f5f5f5")

        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=25, font=('Arial', 10))
        self.style.configure("Treeview.Heading", font=('Arial', 11, 'bold'))
        self.style.map("Treeview.Heading", background=[('active', '#e1e1e1')])

        self.create_widgets()
        self.data = pd.DataFrame()
        self.chunk_size = 1000  # Anzahl der Zeilen, die gleichzeitig geladen werden
        self.indexed_data = {}
        self.file_name = ""
        
        # Flag for loading process
        self.is_loading = False
        
        # For notification window
        self.notification_window = None

    def create_widgets(self):
        # Frame for buttons
        button_frame = tk.Frame(self.root, bg="#f5f5f5")
        button_frame.pack(pady=10, padx=10, fill=tk.X)

        # Upload button
        self.upload_button = tk.Button(button_frame, text="Upload Log", command=self.upload_file, bg="#4CAF50", fg="white", font=('Arial', 10, 'bold'), bd=0, highlightthickness=0)
        self.upload_button.pack(side=tk.LEFT, padx=5)

        # Export button
        self.export_button = tk.Button(button_frame, text="Export Filtered Data", command=self.export_data, bg="#2196F3", fg="white", font=('Arial', 10, 'bold'), bd=0, highlightthickness=0)
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Statistics button
        self.stats_button = tk.Button(button_frame, text="Show Analysis", command=self.show_analysis, bg="#FF9800", fg="white", font=('Arial', 10, 'bold'), bd=0, highlightthickness=0)
        self.stats_button.pack(side=tk.LEFT, padx=5)

        # Search entry
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(button_frame, textvariable=self.search_var, font=('Arial', 10), bd=1, relief=tk.SOLID)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Search button
        self.search_button = tk.Button(button_frame, text="Search", command=self.search_data, bg="#FF5722", fg="white", font=('Arial', 10, 'bold'), bd=0, highlightthickness=0)
        self.search_button.pack(side=tk.LEFT, padx=5)

        # IP Search button
        self.ip_search_button = tk.Button(button_frame, text="Find IP Addresses", command=self.find_ip_addresses, bg="#FF5722", fg="white", font=('Arial', 10, 'bold'), bd=0, highlightthickness=0)
        self.ip_search_button.pack(side=tk.LEFT, padx=5)

        # Treeview for displaying data
        self.tree = ttk.Treeview(self.root, style="Treeview")
        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.tree.bind("<Button-1>", self.sort_column)

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#e0e0e0", font=('Arial', 10))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def show_loading_notification(self):
        """Show a notification window while data is being loaded"""
        if self.notification_window is not None:
            return
            
        self.notification_window = tk.Toplevel(self.root)
        self.notification_window.title("Loading")
        self.notification_window.geometry("300x100")
        self.notification_window.resizable(False, False)
        self.notification_window.transient(self.root)
        self.notification_window.grab_set()
        
        # Center the window
        window_width = 300
        window_height = 100
        screen_width = self.notification_window.winfo_screenwidth()
        screen_height = self.notification_window.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        self.notification_window.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Progress label
        self.progress_var = tk.StringVar()
        self.progress_var.set(f"Loading file: {self.file_name}...")
        progress_label = tk.Label(self.notification_window, textvariable=self.progress_var, font=('Arial', 12))
        progress_label.pack(pady=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.notification_window, mode="indeterminate", length=250)
        self.progress_bar.pack(pady=10)
        self.progress_bar.start(10)
        
        # Update the window
        self.notification_window.update()

    def close_loading_notification(self):
        """Close the loading notification window"""
        if self.notification_window is not None:
            self.progress_bar.stop()
            self.notification_window.grab_release()
            self.notification_window.destroy()
            self.notification_window = None

    def update_loading_progress(self, message):
        """Update the loading progress message"""
        if self.notification_window is not None:
            self.progress_var.set(message)
            self.notification_window.update()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log files", "*.log")])
        if file_path:
            self.file_name = file_path.split("/")[-1]
            self.status_bar.config(text=f"Loading file: {self.file_name}...")
            
            # Use threading to prevent UI freezing during loading
            self.is_loading = True
            loading_thread = threading.Thread(target=self.load_file_with_notification, args=(file_path,))
            loading_thread.daemon = True
            loading_thread.start()

    def load_file_with_notification(self, file_path):
        """Load file with notification updates in a separate thread"""
        try:
            # Show loading notification
            self.root.after(0, self.show_loading_notification)
            
            # Load and process the file
            self.root.after(0, lambda: self.update_loading_progress(f"Loading file: {self.file_name}..."))
            self.load_log_file_in_chunks(file_path)
            
            self.root.after(0, lambda: self.update_loading_progress(f"Indexing data from {self.file_name}..."))
            self.index_data()
            
            self.root.after(0, lambda: self.update_loading_progress(f"Displaying data from {self.file_name}..."))
            
            # Final update on the main thread
            self.root.after(0, self.finish_loading)
        except Exception as e:
            # Handle errors on the main thread
            self.root.after(0, lambda: self.handle_loading_error(str(e)))

    def finish_loading(self):
        """Complete the loading process on the main thread"""
        self.display_data()
        self.status_bar.config(text=f"Loaded {len(self.data)} rows from {self.file_name}")
        self.is_loading = False
        self.close_loading_notification()  # Explicitly close the notification window

    def handle_loading_error(self, error_message):
        """Handle loading errors on the main thread"""
        self.close_loading_notification()  # Make sure to close notification on error too
        messagebox.showerror("Error", f"Failed to read file: {error_message}")
        self.status_bar.config(text="Ready")
        self.is_loading = False

    def load_log_file_in_chunks(self, file_path):
        # Automatically detect delimiter and skip the first row
        try:
            chunks = pd.read_csv(file_path, delimiter=None, chunksize=self.chunk_size, header=None, skip_blank_lines=True, engine='python', on_bad_lines='warn')
            self.data = pd.concat(chunk for chunk in chunks)
            self.data.fillna('', inplace=True)
        except pd.errors.EmptyDataError:
            messagebox.showwarning("Warning", "The file is empty.")
            self.data = pd.DataFrame()

    def index_data(self):
        # Index the data for faster search
        self.indexed_data = {}
        for index, row in self.data.iterrows():
            for col, value in row.items():
                if col not in self.indexed_data:
                    self.indexed_data[col] = {}
                self.indexed_data[col][value] = self.indexed_data[col].get(value, []) + [index]

    def display_data(self):
        # Clear existing data in the Treeview
        for col in self.tree.get_children():
            self.tree.delete(col)

        # Set up new columns
        self.tree["column"] = list(self.data.columns)
        self.tree["show"] = "headings"

        # Configure column headings
        for col in self.tree["column"]:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=100, anchor="w")

        # Insert data rows
        for index, row in self.data.iterrows():
            self.tree.insert("", "end", values=list(row))

        # Adjust column widths
        for col in self.tree["column"]:
            self.tree.column(col, width=max(100, int(max([len(str(x)) for x in self.data[col].values]) * 8)))

    def search_data(self):
        query = self.search_var.get().lower()
        filtered_indices = set()

        # Search using the indexed data
        for col, index_dict in self.indexed_data.items():
            for value, indices in index_dict.items():
                if query in str(value).lower():
                    filtered_indices.update(indices)

        filtered_data = self.data.loc[list(filtered_indices)]
        self.update_treeview(filtered_data)

    def update_treeview(self, data):
        # Clear existing data in the Treeview
        for col in self.tree.get_children():
            self.tree.delete(col)

        # Insert filtered data rows
        for index, row in data.iterrows():
            self.tree.insert("", "end", values=list(row))

    def export_data(self):
        if not self.data.empty:
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if file_path:
                filtered_data = self.data[self.data.apply(lambda row: row.astype(str).str.contains(self.search_var.get().lower()).any(), axis=1)]
                filtered_data.to_csv(file_path, index=False)
                messagebox.showinfo("Export Successful", f"Filtered data exported to {file_path}")

    def show_analysis(self):
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Log Analysis")

        analysis_text = tk.Text(analysis_window, wrap='word', width=100, height=30)
        analysis_text.pack(padx=10, pady=10)

        # Anzahl der IPs, die sich anzumelden versuchten
        unique_ips = self.data[self.data.columns[0]].nunique()
        analysis_text.insert(tk.END, f"Unique IPs attempting to login: {unique_ips}\n\n")

        # Anzahl der Anmeldeversuche pro IP
        login_attempts = self.data[self.data.columns[0]].value_counts()
        analysis_text.insert(tk.END, "Login attempts per IP:\n")
        analysis_text.insert(tk.END, login_attempts.to_string())
        analysis_text.insert(tk.END, "\n\n")

        # Verwendete Usernames
        usernames = self.data[self.data.columns[1]].value_counts()
        analysis_text.insert(tk.END, "Usernames used:\n")
        analysis_text.insert(tk.END, usernames.to_string())
        analysis_text.insert(tk.END, "\n\n")

        # Zuordnung der IPs zu Regionen/Ländern
        # Hier müsste eine API oder Datenbank verwendet werden, um die IPs zu geolokalisieren
        analysis_text.insert(tk.END, "Top 10 countries/regions (requires IP geolocation):\n")
        analysis_text.insert(tk.END, "This feature requires an external IP geolocation service.\n\n")

        # Zuordnung der IPs zu Firmen oder Residential IPs
        analysis_text.insert(tk.END, "IPs associated with companies or residential IPs:\n")
        analysis_text.insert(tk.END, "This feature requires an external IP information service.\n\n")

        # IP-Adressen bereits als negativ aufgefallen
        analysis_text.insert(tk.END, "IPs identified as malicious:\n")
        analysis_text.insert(tk.END, "This feature requires an external IP reputation service.\n\n")

        # Bevorzugte Tageszeiten für die Angriffe
        login_times = self.data[self.data.columns[2]].astype(str).str.extract(r'(\d{2}:\d{2}:\d{2})')[0]
        login_times = login_times.value_counts().sort_index()
        analysis_text.insert(tk.END, "Preferred times for login attempts:\n")
        analysis_text.insert(tk.END, login_times.to_string())

        analysis_text.config(state=tk.DISABLED)

    def sort_column(self, event):
        column = self.tree.identify_column(event.x)[1]
        if hasattr(self, 'sort_direction') and self.sort_direction == 'descending':
            self.data.sort_values(by=column, ascending=True, inplace=True)
            self.sort_direction = 'ascending'
        else:
            self.data.sort_values(by=column, ascending=False, inplace=True)
            self.sort_direction = 'descending'
        self.display_data()

    def find_ip_addresses(self):
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ip_addresses = self.data.applymap(lambda x: ip_pattern.findall(str(x)))
        ip_addresses = ip_addresses[ip_addresses.apply(lambda x: x != [])]

        if not ip_addresses.empty:
            ip_window = tk.Toplevel(self.root)
            ip_window.title("Found IP Addresses")

            ip_tree = ttk.Treeview(ip_window, columns=("IP Address", "Location"), show="headings")
            ip_tree.pack(expand=True, fill=tk.BOTH)

            ip_tree.heading("IP Address", text="IP Address")
            ip_tree.heading("Location", text="Location")
            ip_tree.column("IP Address", width=150, anchor="w")
            ip_tree.column("Location", width=300, anchor="w")

            for index, row in ip_addresses.iterrows():
                for ip in row:
                    if ip:
                        ip_tree.insert("", "end", values=(ip, f"Row {index}"))
        else:
            messagebox.showinfo("IP Search", "No IP addresses found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogViewerApp(root)
    root.mainloop()