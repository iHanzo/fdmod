import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import sys
import time
import threading
import psutil

def update_progress(progress_var, progress_bar, progress_label, progress):
    progress_var.set(progress)
    progress_bar.update()
    progress_label.config(text=f"{progress}%")
    progress_label.update()

def run_dbscan(input_file, columns, eps, min_samples, success_threshold, progress_var, progress_bar, progress_label, chunk_size=1000):
    print("Loading data from:", input_file)
    
    # Read data in chunks to manage memory usage
    chunks = []
    for chunk in pd.read_csv(input_file, chunksize=chunk_size):
        chunks.append(chunk)
    
    data = pd.concat(chunks, axis=0)
    print("Data loaded successfully")
    
    # Display available columns for debugging
    available_columns = data.columns.tolist()
    print("Available columns:", available_columns)
    
    # Check if provided columns exist in the data
    for col in columns:
        if col not in available_columns:
            raise ValueError(f"Column '{col}' not found in the input file. Available columns: {available_columns}")
    
    print("Columns found:", columns)
    # Select the columns for clustering
    clustering_data = data[columns]

    # Convert non-numeric columns to numeric using one-hot encoding
    clustering_data = pd.get_dummies(clustering_data)
    print("Clustering data prepared")

    # Normalize the data
    clustering_data = StandardScaler().fit_transform(clustering_data)
    
    # Update progress bar
    update_progress(progress_var, progress_bar, progress_label, 25)

    # Run DBSCAN
    start_time = time.time()
    db = DBSCAN(eps=eps, min_samples=min_samples, n_jobs=-1).fit(clustering_data)
    end_time = time.time()
    labels = db.labels_
    print("DBSCAN clustering done")

    # Add the cluster labels to the data
    data['ClusterID'] = labels
    print("Cluster labels added to data")

    # Update progress bar
    update_progress(progress_var, progress_bar, progress_label, 50)

    # Create a DataFrame to store cluster information
    cluster_info = []
    for cluster_id in set(labels):
        cluster_data = data[data['ClusterID'] == cluster_id]
        attempts = len(cluster_data)
        successful_attempts = cluster_data['Login Successful'].sum()
        success_rate = successful_attempts / attempts
        attack_ip_rate = cluster_data['Is Attack IP'].mean()
        suspicious = success_rate < success_threshold
        cluster_info.append([cluster_id, attempts, successful_attempts, f"{success_rate:.2%}", suspicious, f"{attack_ip_rate:.2%}"])
    
    cluster_info_df = pd.DataFrame(cluster_info, columns=['Cluster ID', 'Attempts', 'Successful Attempts', 'Success Rate', 'Suspicious', 'Attack IP Rate'])
    cluster_info_df.sort_values(by='Cluster ID', ascending=True, inplace=True)
    # Move cluster -1 to the top
    cluster_info_df = pd.concat([cluster_info_df[cluster_info_df['Cluster ID'] == -1], cluster_info_df[cluster_info_df['Cluster ID'] != -1]])

    duration = end_time - start_time
    rows_per_second = len(data) / duration

    # Update progress bar
    update_progress(progress_var, progress_bar, progress_label, 100)

    return data, cluster_info_df, duration, rows_per_second

def save_output(data, output_file):
    # Reorder columns to have 'ClusterID' at the front
    columns_order = ['ClusterID'] + [col for col in data.columns if col != 'ClusterID']
    data = data[columns_order]
    print("Columns reordered")

    # Save the result to a new CSV file with quoting and UTF-8 encoding
    print(f"Saving clustering results to {output_file}")
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow(data.columns)
        for row in data.itertuples(index=False, name=None):
            writer.writerow(row)
    print("Clustering results saved")
    messagebox.showinfo("Success", f"Clustering results saved to {output_file}")

def save_treeview_output(cluster_info_df, output_file):
    output_dir = os.path.dirname(output_file)
    treeview_output_file = os.path.join(output_dir, "clusterinfo.csv")
    print(f"Saving TreeView information to {treeview_output_file}")
    cluster_info_df.to_csv(treeview_output_file, index=False, quoting=csv.QUOTE_ALL, encoding='utf-8')
    print("TreeView information saved")
    messagebox.showinfo("Success", f"TreeView information saved to {treeview_output_file}")

def browse_file(entry):
    filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def save_file(entry):
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def run_clustering_thread():
    input_file = input_file_entry.get()
    columns = columns_entry.get().split(',')
    columns = [col.strip() for col in columns]  # Remove leading/trailing spaces
    eps = float(eps_entry.get())
    min_samples = int(min_samples_entry.get())
    success_threshold = float(success_threshold_entry.get())

    try:
        data, cluster_info_df, duration, rows_per_second = run_dbscan(input_file, columns, eps, min_samples, success_threshold, progress_var, progress_bar, progress_label)
        
        # Clear existing rows in the treeview
        for i in tree.get_children():
            tree.delete(i)

        # Insert new rows into the treeview
        for row in cluster_info_df.itertuples(index=False):
            tree.insert("", tk.END, values=row)

        # Display statistics and ask to save the output
        if messagebox.askyesno("Clusters Identified", f"{len(cluster_info_df)} clusters identified.\n\n"
                                                     f"Duration: {duration:.2f} seconds\n"
                                                     f"Rows per second: {rows_per_second:.2f}\n\n"
                                                     f"Do you want to save the output?"):
            output_file = output_file_entry.get()
            save_output(data, output_file)

            # Automatically save the TreeView output
            save_treeview_output(cluster_info_df, output_file)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def run_clustering():
    thread = threading.Thread(target=run_clustering_thread)
    thread.start()

def reset_app():
    python = sys.executable
    os.execl(python, python, *sys.argv)

def sort_column(tree, col, reverse):
    data_list = [(tree.set(k, col), k) for k in tree.get_children('')]
    try:
        data_list.sort(key=lambda t: float(t[0].replace('%', '')) if '%' in t[0] else float(t[0]), reverse=reverse)
    except ValueError:
        data_list.sort(reverse=reverse)

    for index, (val, k) in enumerate(data_list):
        tree.move(k, '', index)

    tree.heading(col, command=lambda _col=col: sort_column(tree, _col, not reverse))

# Create the main window
root = tk.Tk()
root.title("DBSCAN Clustering")

# Create and place widgets
tk.Label(root, text="Input CSV File:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=0, column=1, padx=5, pady=5)
input_file_entry.insert(0, 'input\logins5k.csv')  # Adjust path for Windows
tk.Button(root, text="Browse", command=lambda: browse_file(input_file_entry)).grid(row=0, column=2, padx=5, pady=5)

tk.Label(root, text="Output CSV File:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=1, column=1, padx=5, pady=5)
output_file_entry.insert(0, 'output\output.csv')  # Adjust path for Windows
tk.Button(root, text="Browse", command=lambda: save_file(output_file_entry)).grid(row=1, column=2, padx=5, pady=5)

tk.Label(root, text="Columns (comma-separated):").grid(row=2, column=0, padx=5, pady=5, sticky='e')
columns_entry = tk.Entry(root, width=50)
columns_entry.grid(row=2, column=1, padx=5, pady=5)
columns_entry.insert(0, 'User ID, IP Address, User Agent String, Browser Name and Version, OS Name and Version, Device Type')

tk.Label(root, text="Epsilon:").grid(row=3, column=0, padx=5, pady=5, sticky='e')
eps_entry = tk.Entry(root, width=50)
eps_entry.grid(row=3, column=1, padx=5, pady=5)
eps_entry.insert(0, '0.5')

tk.Label(root, text="Min Samples:").grid(row=4, column=0, padx=5, pady=5, sticky='e')
min_samples_entry = tk.Entry(root, width=50)
min_samples_entry.grid(row=4, column=1, padx=5, pady=5)
min_samples_entry.insert(0, '5')

tk.Label(root, text="Success Threshold:").grid(row=5, column=0, padx=5, pady=5, sticky='e')
success_threshold_entry = tk.Entry(root, width=50)
success_threshold_entry.grid(row=5, column=1, padx=5, pady=5)
success_threshold_entry.insert(0, '0.5')

tk.Button(root, text="Run Clustering", command=run_clustering).grid(row=6, column=0, columnspan=3, pady=10)
tk.Button(root, text="Reset", command=reset_app).grid(row=7, column=0, columnspan=3, pady=10)

# Progress bar with percentage label
progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky='ew')
progress_label = tk.Label(root, text="0%")
progress_label.grid(row=8, column=0, columnspan=3)

# Frame and scrollbar for the treeview
frame = tk.Frame(root)
frame.grid(row=9, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Treeview to display cluster information
columns = ('Cluster ID', 'Attempts', 'Successful Attempts', 'Success Rate', 'Suspicious', 'Attack IP Rate')
tree = ttk.Treeview(frame, columns=columns, show='headings', yscrollcommand=scrollbar.set)
for col in columns:
    tree.heading(col, text=col, anchor=tk.CENTER, command=lambda _col=col: sort_column(tree, _col, False))
    tree.column(col, anchor=tk.CENTER, width=150)
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.config(command=tree.yview)

# Increase header height and wrap text
style = ttk.Style()
style.configure("Treeview.Heading", wraplength=150, height=40)

# Run the main event loop
root.mainloop()