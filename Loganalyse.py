import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import re
import requests # Note: requests is imported but not used in the provided logic
import threading
import os # For getting filename

# --- Constants (Optional but recommended) ---
# Example: If your logs reliably have headers or a fixed structure
# IP_COLUMN_NAME = 'Src IP' 
# USER_COLUMN_NAME = 'User'
# TIMESTAMP_COLUMN_NAME = 'Timestamp'
# Or use indices if no headers
IP_COLUMN_INDEX = 0
USER_COLUMN_INDEX = 1 # Assuming username is the second column
TIMESTAMP_COLUMN_INDEX = 2 # Assuming timestamp is the third column
NUM_COLS_TO_CHECK_FOR_IPS = 5 # How many columns to search in find_ip_addresses

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Log Analyzer (Optimized)")
        self.root.geometry("1100x700") # Slightly larger default size
        self.root.configure(bg="#f5f5f5")

        self.style = ttk.Style()
        self.style.theme_use('clam') # Try a different theme for potentially better looks
        self.style.configure("Treeview", rowheight=25, font=('Arial', 10), background="#ffffff", fieldbackground="#ffffff")
        self.style.configure("Treeview.Heading", font=('Arial', 11, 'bold'), background="#e1e1e1", relief="flat")
        self.style.map("Treeview.Heading", background=[('active', '#d1d1d1')])
        self.style.configure("TButton", padding=6, relief="flat", background="#e1e1e1", font=('Arial', 10, 'bold'))
        self.style.map("TButton", background=[('active', '#c1c1c1')])
        self.style.configure("TEntry", padding=5, relief="flat")
        self.style.configure("TProgressbar", thickness=20)

        self.create_widgets()
        self.data = pd.DataFrame() # Holds the original full log data
        self.displayed_data = pd.DataFrame() # Holds the data currently shown in the treeview
        self.chunk_size = 5000  # Increased chunk size for potentially faster loading
        self.file_name = ""
        self.is_loading = False
        self.notification_window = None

    def create_widgets(self):
        # --- Top Frame for Controls ---
        control_frame = tk.Frame(self.root, bg="#e0e0e0", bd=1, relief=tk.SUNKEN)
        control_frame.pack(pady=(0, 5), padx=0, fill=tk.X)

        button_frame = tk.Frame(control_frame, bg="#e0e0e0")
        button_frame.pack(pady=5, padx=10, side=tk.LEFT)
        
        search_frame = tk.Frame(control_frame, bg="#e0e0e0")
        search_frame.pack(pady=5, padx=10, side=tk.LEFT, fill=tk.X, expand=True)

        # --- Buttons ---
        # Using ttk.Button for better styling consistency
        self.upload_button = ttk.Button(button_frame, text="Upload Log", command=self.upload_file, style="TButton")
        self.upload_button.grid(row=0, column=0, padx=5, pady=2)

        self.export_button = ttk.Button(button_frame, text="Export Displayed Data", command=self.export_data, style="TButton")
        self.export_button.grid(row=0, column=1, padx=5, pady=2)

        self.stats_button = ttk.Button(button_frame, text="Show Analysis", command=self.show_analysis, style="TButton")
        self.stats_button.grid(row=0, column=2, padx=5, pady=2)

        self.ip_search_button = ttk.Button(button_frame, text="Find IP Addresses", command=self.find_ip_addresses, style="TButton")
        self.ip_search_button.grid(row=0, column=3, padx=5, pady=2)
        
        # --- Search ---
        search_label = ttk.Label(search_frame, text="Search:", background="#e0e0e0", font=('Arial', 10))
        search_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 10), width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_entry.bind("<Return>", lambda event: self.search_data()) # Search on Enter key

        self.search_button = ttk.Button(search_frame, text="Search", command=self.search_data, style="TButton")
        self.search_button.pack(side=tk.LEFT, padx=5)

        # --- Treeview Frame (to contain Treeview and Scrollbar) ---
        tree_frame = tk.Frame(self.root, bg="#f5f5f5")
        tree_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=(0, 5))

        # --- Treeview ---
        self.tree = ttk.Treeview(tree_frame, style="Treeview", show="headings")
        
        # Vertical Scrollbar
        self.scrollbar_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar_y.set)

        # Horizontal Scrollbar
        self.scrollbar_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=self.scrollbar_x.set)
        
        # Pack Treeview and Scrollbars
        self.scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(expand=True, fill=tk.BOTH) # Pack treeview last

        # --- Status Bar ---
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#e0e0e0", font=('Arial', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def show_loading_notification(self):
        if self.notification_window is not None and self.notification_window.winfo_exists():
            self.notification_window.lift()
            return
            
        self.notification_window = tk.Toplevel(self.root)
        self.notification_window.title("Loading...")
        # Prevent closing via 'X' button during critical load phase
        self.notification_window.protocol("WM_DELETE_WINDOW", lambda: None) 
        self.notification_window.geometry("350x120")
        self.notification_window.resizable(False, False)
        self.notification_window.transient(self.root) # Show above main window
        self.notification_window.grab_set() # Block interaction with main window

        # Center the window
        self.root.update_idletasks() # Ensure root window geometry is updated
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        
        win_w = 350
        win_h = 120
        center_x = root_x + (root_w // 2) - (win_w // 2)
        center_y = root_y + (root_h // 2) - (win_h // 2)
        self.notification_window.geometry(f'{win_w}x{win_h}+{center_x}+{center_y}')
        
        # Progress label
        self.progress_var = tk.StringVar()
        self.progress_var.set(f"Initializing load for {os.path.basename(self.file_name)}...")
        progress_label = ttk.Label(self.notification_window, textvariable=self.progress_var, font=('Arial', 10), wraplength=330)
        progress_label.pack(pady=(15, 5), padx=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.notification_window, mode="indeterminate", length=300)
        self.progress_bar.pack(pady=10, padx=10)
        self.progress_bar.start(15) # Speed of animation
        
        self.notification_window.update()

    def close_loading_notification(self):
        if self.notification_window is not None and self.notification_window.winfo_exists():
            self.progress_bar.stop()
            self.notification_window.grab_release()
            self.notification_window.destroy()
            self.notification_window = None

    def update_loading_progress(self, message):
        if self.notification_window is not None and self.notification_window.winfo_exists():
            self.progress_var.set(message)
            self.notification_window.update() # Force UI update

    def upload_file(self):
        if self.is_loading:
             messagebox.showwarning("Busy", "Please wait for the current operation to complete.")
             return
             
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.file_name = file_path # Store full path
            base_name = os.path.basename(file_path)
            self.status_bar.config(text=f"Starting to load: {base_name}...")
            self.root.update_idletasks() # Show status immediately
            
            # Clear previous data
            self.data = pd.DataFrame()
            self.display_data(self.data) # Clear Treeview

            self.is_loading = True
            # Disable buttons during load
            self.toggle_controls(enabled=False)

            # Use threading to prevent UI freezing
            loading_thread = threading.Thread(target=self.load_file_with_notification, args=(file_path,), daemon=True)
            loading_thread.start()

    def load_file_with_notification(self, file_path):
        """Load file with notification updates in a separate thread"""
        try:
            base_name = os.path.basename(file_path)
            # Show loading notification (scheduled on main thread)
            self.root.after(0, self.show_loading_notification)
            
            # Load and process the file
            self.root.after(0, lambda: self.update_loading_progress(f"Reading {base_name}... (This may take a while for large files)"))
            self.load_log_file_in_chunks(file_path)
            
            # --- Indexing step removed ---
            
            self.root.after(0, lambda: self.update_loading_progress(f"Preparing display for {base_name}..."))
            
            # Final update on the main thread
            self.root.after(0, self.finish_loading)

        except Exception as e:
            # Handle errors on the main thread
            error_msg = f"Failed to read or process file:\n{e}"
            self.root.after(0, lambda: self.handle_loading_error(error_msg))

    def finish_loading(self):
        """Complete the loading process on the main thread"""
        base_name = os.path.basename(self.file_name)
        if not self.data.empty:
             self.display_data(self.data) # Display the full loaded data initially
             self.adjust_column_widths(self.data.head(100)) # Adjust widths based on sample
             self.status_bar.config(text=f"Loaded {len(self.data):,} rows from {base_name}")
        else:
             self.status_bar.config(text=f"File loaded but appears empty or could not be parsed: {base_name}")
        
        self.is_loading = False
        self.toggle_controls(enabled=True) # Re-enable buttons
        self.close_loading_notification()

    def handle_loading_error(self, error_message):
        """Handle loading errors on the main thread"""
        self.close_loading_notification()
        messagebox.showerror("Loading Error", error_message)
        self.status_bar.config(text="Ready")
        self.is_loading = False
        self.toggle_controls(enabled=True)
        # Clear potentially partially loaded data
        self.data = pd.DataFrame()
        self.display_data(self.data)

    def load_log_file_in_chunks(self, file_path):
        """Reads the log file using pandas read_csv with chunking."""
        chunks = []
        try:
            # Using engine='python' is necessary for delimiter=None
            # 'warn' will show warnings for bad lines but continue
            # 'skipinitialspace' can help if delimiters have extra spaces
            # Low_memory=False might help with mixed types, but uses more RAM
            iterator = pd.read_csv(
                file_path,
                delimiter=None, # Auto-detect delimiter
                chunksize=self.chunk_size,
                header=None, # Assume no header row in typical logs
                skip_blank_lines=True,
                on_bad_lines='warn', 
                engine='python',
                encoding='utf-8', # Specify encoding if known, utf-8 is common
                encoding_errors='replace', # Replace chars that cause encoding errors
                low_memory=False,
                skipinitialspace=True 
            )
            
            processed_rows = 0
            base_name = os.path.basename(file_path)
            for i, chunk in enumerate(iterator):
                 chunks.append(chunk)
                 processed_rows += len(chunk)
                 # Update progress less frequently to avoid too many UI updates
                 if i % 10 == 0: 
                      self.root.after(0, lambda p=processed_rows: self.update_loading_progress(f"Read {p:,} rows from {base_name}..."))

            if chunks:
                self.data = pd.concat(chunks, ignore_index=True)
                # Convert all columns to string initially to avoid type issues later
                # This uses more memory but increases robustness for diverse logs
                for col in self.data.columns:
                    self.data[col] = self.data[col].astype(str)
                self.data.fillna('', inplace=True) # Replace any remaining NaN/None with empty string
            else:
                self.data = pd.DataFrame() # Ensure empty DataFrame if no chunks were read

        except pd.errors.EmptyDataError:
            self.data = pd.DataFrame() # Handle completely empty file
            self.root.after(0, lambda: messagebox.showwarning("Warning", "The selected file is empty."))
        except FileNotFoundError:
             raise Exception(f"File not found: {file_path}") # Re-raise for central handling
        except Exception as e:
             # Catch other potential pandas or file reading errors
             raise Exception(f"Error during CSV parsing: {e}")


    def display_data(self, df_to_display):
        """Clears and repopulates the Treeview with the provided DataFrame."""
        # Clear existing data efficiently
        self.tree.delete(*self.tree.get_children())

        # Store the data currently being displayed
        self.displayed_data = df_to_display.copy() if df_to_display is not None else pd.DataFrame()

        if self.displayed_data.empty:
            self.tree["columns"] = []
            self.tree.heading("#0", text="") # Clear default column if needed
            # Optionally display a message in the treeview area
            # self.tree.insert("", "end", text="No data to display.") 
            return

        # Set up new columns
        cols = list(self.displayed_data.columns)
        self.tree["columns"] = cols
        self.tree["show"] = "headings"

        # Configure column headings and set up sorting command
        for col in cols:
            # Ensure initial sort is ascending
            self.tree.heading(col, text=str(col), command=lambda c=col: self.sort_treeview_column(c, False))
            self.tree.column(col, width=100, anchor="w", stretch=tk.NO) # Default width, no stretch initially

        # Insert data rows using iid for potential future reference
        # Using .values is generally faster than iterrows for large data
        for index, row in enumerate(self.displayed_data.values):
             # Ensure all values are strings for display
             values_str = [str(v) for v in row]
             try:
                  self.tree.insert("", "end", iid=index, values=values_str)
             except Exception as e:
                  print(f"Error inserting row {index}: {values_str} - {e}") # Debugging output
                  # Skip row on error or handle differently
                  continue

    def adjust_column_widths(self, df_sample):
        """Adjusts column widths based on header and a sample of the data."""
        if df_sample is None or df_sample.empty:
             return
             
        for col in self.tree["columns"]:
            # Header width
            header_text = str(self.tree.heading(col)['text'])
            header_width = len(header_text) * 8 + 20  # Estimate width based on chars + padding

            # Sample data width
            sample_width = 0
            try:
                # Ensure column exists in the sample and get max length
                if col in df_sample.columns:
                     # Use a limited sample size for performance
                     sample_size = min(100, len(df_sample)) 
                     # Convert to string, find length, get max of the sample
                     str_series = df_sample[col].head(sample_size).astype(str)
                     # Pandas < 2.0 needs dropna() before .str
                     # Pandas >= 2.0 handles NA within .str
                     # Use try-except for safety
                     try:
                         max_len = str_series.str.len().max()
                         if pd.notna(max_len):
                            sample_width = int(max_len * 7 + 20) # Estimate width + padding
                     except Exception: # Catch potential errors during str operations
                         pass 
                else:
                     print(f"Warning: Column '{col}' not found in sample data for width calculation.")

            except Exception as e:
                print(f"Error calculating sample width for column '{col}': {e}")
                sample_width = 100 # Default fallback

            # Set width: max of header, sample (if calculated), and a minimum
            final_width = max(header_width, sample_width, 80)
            self.tree.column(col, width=final_width, anchor="w")

    def update_treeview(self, data):
        """Convenience function to update the treeview with new data."""
        self.display_data(data)
        # Adjust widths after updating, using a sample of the *new* data
        if data is not None and not data.empty:
            self.adjust_column_widths(data.head(100))
        else:
             self.adjust_column_widths(pd.DataFrame()) # Clear widths if data is empty

    def sort_treeview_column(self, col, reverse):
        """Sorts the Treeview data by a specific column without modifying self.data."""
        if self.is_loading:
            return
            
        # Get data directly from the treeview (list of tuples: (value, item_id))
        # Treeview stores everything as strings, so comparisons might be string-based
        # For true numeric sort, you'd need to convert, which can be slow/error-prone here
        try:
            data_list = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        except tk.TclError:
            # Handle cases where column might not exist (shouldn't happen with current logic)
             print(f"Error getting data for sorting column: {col}")
             return

        # Attempt numeric sort if possible, fallback to string sort
        try:
            # Try converting to float for sorting
            numeric_list = [(float(value), iid) for value, iid in data_list]
            numeric_list.sort(key=lambda x: x[0], reverse=reverse)
            sorted_list = numeric_list
        except ValueError:
            # Fallback to case-insensitive string sort
            data_list.sort(key=lambda x: str(x[0]).lower(), reverse=reverse)
            sorted_list = data_list
        except Exception as e:
             print(f"Sorting error: {e}, using basic string sort.")
             # Basic string sort as ultimate fallback
             data_list.sort(key=lambda x: str(x[0]), reverse=reverse)
             sorted_list = data_list


        # Reorder items in the treeview
        for index, (val, k) in enumerate(sorted_list):
            self.tree.move(k, '', index)

        # Update the heading command to toggle direction
        self.tree.heading(col, command=lambda c=col: self.sort_treeview_column(c, not reverse))
        
        # Optional: Add visual indicator (up/down arrow) to the sorted column header
        # (Requires more complex header text manipulation)

    def search_data(self):
        """Filters the main DataFrame and updates the Treeview."""
        if self.is_loading: return
        
        query = self.search_var.get().strip()
        
        if not query: # If search is empty, show all data
            self.update_treeview(self.data)
            self.status_bar.config(text=f"Displaying all {len(self.data):,} rows")
            return
            
        if self.data is None or self.data.empty:
            self.update_treeview(pd.DataFrame()) # Show empty
            self.status_bar.config(text="No data loaded to search")
            return

        self.status_bar.config(text=f"Searching for '{query}'...")
        self.root.update_idletasks()

        try:
            # Perform case-insensitive search across all columns (converted to string)
            mask = self.data.apply(
                lambda col: col.astype(str).str.contains(query, case=False, na=False, regex=False)
            ).any(axis=1)
            
            filtered_data = self.data.loc[mask]
            self.update_treeview(filtered_data) # Display filtered results
            self.status_bar.config(text=f"Found {len(filtered_data):,} matching rows for '{query}'")

        except Exception as e:
            messagebox.showerror("Search Error", f"An error occurred during search:\n{e}")
            self.status_bar.config(text="Search error")
            self.update_treeview(self.data) # Revert to showing all data on error


    def export_data(self):
        """Exports the data currently displayed in the Treeview."""
        if self.is_loading:
            messagebox.showwarning("Busy", "Please wait for the current operation to complete.")
            return

        if self.displayed_data is None or self.displayed_data.empty:
            messagebox.showinfo("Export", "No data is currently displayed to export.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Displayed Data As",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Excel files", "*.xlsx"), ("All files", "*.*")],
            initialfile="filtered_log_export" # Suggest default filename
        )
        
        if file_path:
            try:
                self.status_bar.config(text=f"Exporting {len(self.displayed_data):,} rows...")
                self.root.update_idletasks()
                
                if file_path.endswith('.xlsx'):
                     # Check if openpyxl is installed
                     try:
                         import openpyxl
                     except ImportError:
                         messagebox.showerror("Missing Library", "Exporting to .xlsx requires the 'openpyxl' library.\nPlease install it (pip install openpyxl) and restart.")
                         self.status_bar.config(text="Export cancelled: Missing library")
                         return
                     self.displayed_data.to_excel(file_path, index=False, engine='openpyxl')
                else: # Default to CSV
                     self.displayed_data.to_csv(file_path, index=False, encoding='utf-8')
                
                messagebox.showinfo("Export Successful", f"Displayed data successfully exported to:\n{file_path}")
                self.status_bar.config(text="Export complete")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data:\n{e}")
                self.status_bar.config(text="Export failed")


    def show_analysis(self):
        """Shows basic analysis in a new window."""
        if self.is_loading:
            messagebox.showwarning("Busy", "Please wait for the current operation to complete.")
            return

        if self.data is None or self.data.empty:
            messagebox.showinfo("Analysis", "No data loaded to analyze.")
            return

        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Log Analysis")
        analysis_window.geometry("600x500")
        
        analysis_text = tk.Text(analysis_window, wrap='word', width=80, height=25, font=('Courier New', 10))
        analysis_scrollbar = ttk.Scrollbar(analysis_window, orient="vertical", command=analysis_text.yview)
        analysis_text.configure(yscrollcommand=analysis_scrollbar.set)
        
        analysis_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        analysis_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        analysis_content = f"--- Log Analysis for {os.path.basename(self.file_name)} ---\n"
        analysis_content += f"Total Rows: {len(self.data):,}\n\n"

        # --- Analysis based on assumed column indices (Update if structure is known) ---
        try:
            # Example: Unique IPs (assuming IP is in the first column)
            if IP_COLUMN_INDEX < len(self.data.columns):
                ip_col_name = self.data.columns[IP_COLUMN_INDEX]
                unique_ips = self.data[ip_col_name].nunique()
                analysis_content += f"Unique values in Column {IP_COLUMN_INDEX} (Potential IPs): {unique_ips:,}\n"
                
                login_attempts = self.data[ip_col_name].value_counts().head(20) # Top 20
                analysis_content += f"\nTop 20 most frequent values in Column {IP_COLUMN_INDEX}:\n"
                analysis_content += login_attempts.to_string()
                analysis_content += "\n\n"
            else:
                 analysis_content += f"Column {IP_COLUMN_INDEX} (Potential IPs) not found.\n\n"

            # Example: Usernames (assuming user is in the second column)
            if USER_COLUMN_INDEX < len(self.data.columns):
                 user_col_name = self.data.columns[USER_COLUMN_INDEX]
                 usernames = self.data[user_col_name].value_counts().head(20) # Top 20
                 analysis_content += f"Top 20 most frequent values in Column {USER_COLUMN_INDEX} (Potential Usernames):\n"
                 analysis_content += usernames.to_string()
                 analysis_content += "\n\n"
            else:
                 analysis_content += f"Column {USER_COLUMN_INDEX} (Potential Usernames) not found.\n\n"

            # Example: Login Times (assuming timestamp is in the third column)
            if TIMESTAMP_COLUMN_INDEX < len(self.data.columns):
                time_col_name = self.data.columns[TIMESTAMP_COLUMN_INDEX]
                # More robust time extraction (handles common HH:MM:SS formats)
                # Extracts first HH:MM:SS found in the string
                time_pattern = r'(\d{1,2}:\d{1,2}:\d{1,2})'
                extracted_times = self.data[time_col_name].astype(str).str.extract(time_pattern, expand=False).dropna()
                
                if not extracted_times.empty:
                    # Extract hour for hourly analysis
                    hours = pd.to_datetime(extracted_times, format='%H:%M:%S', errors='coerce').dt.hour.dropna().astype(int)
                    if not hours.empty:
                         hourly_counts = hours.value_counts().sort_index()
                         analysis_content += f"Counts per Hour (extracted from Column {TIMESTAMP_COLUMN_INDEX}):\n"
                         analysis_content += hourly_counts.to_string()
                         analysis_content += "\n\n"
                    else:
                        analysis_content += f"Could not extract valid hours from Column {TIMESTAMP_COLUMN_INDEX}.\n\n"
                else:
                     analysis_content += f"No time patterns (HH:MM:SS) found in Column {TIMESTAMP_COLUMN_INDEX}.\n\n"
            else:
                 analysis_content += f"Column {TIMESTAMP_COLUMN_INDEX} (Potential Timestamp) not found.\n\n"

        except Exception as e:
            analysis_content += f"\n--- Error during analysis ---\n{e}\n"
            analysis_content += "Check column indices/names and data format.\n"

        # --- Placeholders for external lookups ---
        analysis_content += "--- External Lookups (Not Implemented) ---\n"
        analysis_content += "* IP Geolocation (Country/Region)\n"
        analysis_content += "* IP Reputation (Malicious IP Check)\n"
        analysis_content += "* IP Organization/Type (Company/Residential)\n"

        # Insert content and disable editing
        analysis_text.insert(tk.END, analysis_content)
        analysis_text.config(state=tk.DISABLED)


    def find_ip_addresses(self):
        """Finds unique IP addresses in the first few columns and displays them."""
        if self.is_loading: return
        if self.data is None or self.data.empty:
            messagebox.showinfo("IP Search", "No data loaded.")
            return

        # Regex for IPv4 addresses (basic pattern)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        found_ips = set()

        # Limit search to a few initial columns for performance
        cols_to_check_indices = range(min(NUM_COLS_TO_CHECK_FOR_IPS, len(self.data.columns)))
        cols_names_to_check = [self.data.columns[i] for i in cols_to_check_indices]

        self.status_bar.config(text=f"Searching for IPs in first {len(cols_names_to_check)} columns...")
        self.root.update_idletasks()

        try:
            for col_name in cols_names_to_check:
                # Convert column to string, find all matches, handle potential errors
                series_str = self.data[col_name].astype(str)
                all_matches = series_str.str.findall(ip_pattern).explode().dropna()
                
                # Validate IPs more strictly (optional but good)
                valid_ips_in_col = {ip for ip in all_matches if self.is_valid_ipv4(ip)}
                found_ips.update(valid_ips_in_col)

            self.status_bar.config(text="IP search finished.")

            if found_ips:
                self.display_ip_results(found_ips)
            else:
                messagebox.showinfo("IP Search", f"No valid IP addresses found in the first {len(cols_names_to_check)} columns.")
        
        except Exception as e:
            messagebox.showerror("IP Search Error", f"An error occurred during IP search:\n{e}")
            self.status_bar.config(text="IP search error")

    def is_valid_ipv4(self, ip_str):
        """Checks if a string is a valid IPv4 address."""
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False # Contains non-numeric parts

    def display_ip_results(self, ip_set):
        """Displays the found unique IP addresses in a new window with Listbox."""
        ip_window = tk.Toplevel(self.root)
        ip_window.title(f"Found {len(ip_set)} Unique Valid IP Addresses")
        ip_window.geometry("350x450")

        # Frame for Listbox and Scrollbar
        list_frame = tk.Frame(ip_window)
        list_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        ip_scrollbar = ttk.Scrollbar(list_frame, orient="vertical")
        ip_listbox = tk.Listbox(list_frame, font=('Courier New', 10), yscrollcommand=ip_scrollbar.set, selectmode=tk.EXTENDED)
        ip_scrollbar.config(command=ip_listbox.yview)

        ip_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        ip_listbox.pack(expand=True, fill=tk.BOTH)

        # Sort IPs numerically for better readability
        try:
             sorted_ips = sorted(list(ip_set), key=lambda ip: list(map(int, ip.split('.'))))
        except ValueError:
             sorted_ips = sorted(list(ip_set)) # Fallback to lexical sort

        for ip in sorted_ips:
            ip_listbox.insert(tk.END, ip)

        # Add a button to copy selected IPs to clipboard
        def copy_selected_ips():
            selected_indices = ip_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Copy IPs", "No IPs selected.", parent=ip_window)
                return
            
            selected_ips_text = "\n".join([ip_listbox.get(i) for i in selected_indices])
            
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_ips_text)
                messagebox.showinfo("Copy IPs", f"{len(selected_indices)} IP(s) copied to clipboard.", parent=ip_window)
            except tk.TclError:
                 messagebox.showerror("Copy Error", "Could not access clipboard.", parent=ip_window)

        copy_button = ttk.Button(ip_window, text="Copy Selected to Clipboard", command=copy_selected_ips)
        copy_button.pack(pady=(0, 10))


    def toggle_controls(self, enabled=True):
        """Enable or disable main control buttons."""
        state = tk.NORMAL if enabled else tk.DISABLED
        widgets_to_toggle = [
            self.upload_button, self.export_button, self.stats_button, 
            self.ip_search_button, self.search_entry, self.search_button
        ]
        for widget in widgets_to_toggle:
            try:
                 # Handle both tk and ttk widgets if necessary
                 if isinstance(widget, (ttk.Button, ttk.Entry)):
                      widget.configure(state=state)
                 elif isinstance(widget, tk.Button): # Original buttons if not changed to ttk
                      widget.config(state=state)
            except tk.TclError:
                # Ignore errors if widget doesn't exist or is already destroyed
                pass

# --- Main execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = LogViewerApp(root)
    root.mainloop()