import tkinter as tk 
from tkinter import ttk

import os, shutil, errno, stat, paramiko, subprocess, json, logging


# Top level window 
frame = tk.Tk() 
frame.title("Export IS Assets Tool (New Line Separated)") 
frame.geometry('1000x500') 
# Function for getting Input 
# from textbox and printing it  
# at label widget 
app_data_dir = os.getenv('LOCALAPPDATA') + '\\ISExport'
app_data_file = app_data_dir+"\\ISExport.json"
server_popup_open = False

logs_text = tk.Text(undo=True)

class WidgetLogger(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.setLevel(logging.DEBUG)
        self.widget = widget
        self.widget.config(state='disabled')
        self.widget.tag_config("INFO", foreground="black")
        self.widget.tag_config("DEBUG", foreground="grey")
        self.widget.tag_config("WARNING", foreground="orange")
        self.widget.tag_config("ERROR", foreground="red")
        self.widget.tag_config("CRITICAL", foreground="red", underline=1)

        self.red = self.widget.tag_configure("red", foreground="red")
    def emit(self, record):
        self.widget.config(state='normal')
        # Append message (record) to the widget
        self.widget.insert(tk.END, self.format(record) + '\n', record.levelname)
        self.widget.see(tk.END)  # Scroll to the bottom
        self.widget.config(state='disabled') 
        self.widget.update() # Refresh the widget

widget_logger = WidgetLogger(logs_text)
formatter = logging.Formatter(
    '%(asctime)s -- %(message)s')
widget_logger.setFormatter(formatter)
logger = logging.getLogger(__name__)

logger.addHandler(widget_logger)


if not os.path.exists(app_data_dir):
    os.mkdir(app_data_dir)
    f = open(app_data_file, "a")
    f.write("{}") #write empty json
    f.close()
elif not os.path.isfile(app_data_file):
    f = open(app_data_file, "a")
    f.write("{}") #write empty json
    f.close()
    
servers_config = "{}"
servers_config_keys = []
servers_config_keys_var = tk.StringVar(value=servers_config_keys)

def server_popup(server_name=None):
    global servers_config, server_popup_open
    if not server_popup_open:
        server_popup_open = True
    else:
        return
    server = servers_config[server_name] if server_name else None
    add_server_top = tk.Toplevel(frame)
    add_server_top.protocol("WM_DELETE_WINDOW", lambda: on_close_server_popup(add_server_top))

    add_server_top.geometry("600x300")
    add_server_top.title("Server Window")
    entry_data = {}
    tk.Label(add_server_top, text="Name (Unique): ").place(x=10,y=30)
    entry_data["name_entry"]=tk.Entry(add_server_top)
    entry_data["name_entry"].insert(0, server_name if server_name else "")
    entry_data["name_entry"].place(x=180,y=30, width=400, height=30)
    tk.Label(add_server_top, text="Local Path to IS Packages: ").place(x=10,y=60)
    entry_data["local_entry"]=tk.Entry(add_server_top)
    entry_data["local_entry"].insert(0, server["local_path"] if server and server["local_path"] is not None else "")
    entry_data["local_entry"].place(x=180,y=60, width=400, height=30)
    tk.Label(add_server_top, text="Remote Path to IS Packages: ").place(x=10,y=90)
    entry_data["remote_entry"]=tk.Entry(add_server_top)
    entry_data["remote_entry"].insert(0, server["remote_path"] if server and server["remote_path"] is not None else "")
    entry_data["remote_entry"].place(x=180,y=90, width=400, height=30)
    tk.Label(add_server_top, text="Server IP: ").place(x=10,y=120)
    entry_data["server_ip_entry"]=tk.Entry(add_server_top)
    entry_data["server_ip_entry"].insert(0, server["server_ip"] if server and server["server_ip"] is not None else "")
    entry_data["server_ip_entry"].place(x=180,y=120, width=400, height=30)
    tk.Label(add_server_top, text="Server SSH Port: ").place(x=10,y=150)
    entry_data["server_port_entry"]=tk.Entry(add_server_top)
    entry_data["server_port_entry"].insert(0, server["server_port"] if server and server["server_port"] is not None else "")
    entry_data["server_port_entry"].place(x=180,y=150, width=400, height=30)
    tk.Label(add_server_top, text="Username: ").place(x=10,y=180)
    entry_data["username_entry"]=tk.Entry(add_server_top)
    entry_data["username_entry"].insert(0, server["server_ssh_username"] if server and server["server_ssh_username"] is not None else "")
    entry_data["username_entry"].place(x=180,y=180, width=400, height=30)
    tk.Label(add_server_top, text="Password: ").place(x=10,y=210)
    entry_data["password_entry"]=tk.Entry(add_server_top, show='*')
    entry_data["password_entry"].insert(0, server["server_ssh_password"] if server and server["server_ssh_password"] is not None else "")
    entry_data["password_entry"].place(x=180,y=210, width=400, height=30)
    add_button = tk.Button(add_server_top, 
                        text = "Save" if server_name else "Add", 
                        background="#ffffbf",
                        font="bold",
                        foreground="black",
                        command = lambda: add_server(entry_data, add_server_top)) 
    add_button.place(x=520,y=250)


def delete_server():
    global servers_config, servers_config_keys
    logger.info("Deleting server..")
    server_to_delete = ""
    if len(servers_config_keys) > 0:
        server_to_delete = servers_dropdown.get()
        servers_config_keys.remove(server_to_delete)
        del servers_config[server_to_delete]
        servers_dropdown["values"] = servers_config_keys
        if len(servers_config_keys) > 0:
            servers_dropdown.current(0)
        else:
            servers_dropdown.set("")
        set_configs_from_json(servers_config[servers_dropdown.get()] if len(servers_config_keys) > 0 else None)
        update_config_file_on_disk()
        logger.info("Server \"{0}\" deleted successfully!".format(server_to_delete))

def export_files():
    
    global remote_path, local_path
    try:
        inp = is_assets_input.get(1.0, "end-1c")
        if inp is None or inp == "":
            return
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info("Connecting to: "+ server_ip+":"+server_port)
        ssh.connect(server_ip, username=server_ssh_username, password=server_ssh_password, port=server_port)
        sftp = ssh.open_sftp()
        

        assets = ("".join([s for s in inp.strip().splitlines(True) if s.strip()])).splitlines()
        for a in assets:
            a = a.strip()
            path_of_asset = name_to_path(a)
            logger.info(remote_path + path_of_asset)
            path_of_asset_in_repo =  path_of_asset
            logger.info(local_path +path_of_asset_in_repo)
            if stat.S_ISDIR(sftp.stat(remote_path + path_of_asset).st_mode):
                download_files(sftp, remote_path + path_of_asset + '/', local_path +path_of_asset_in_repo)
            else:
                logger.info((local_path +path_of_asset_in_repo).replace("\\", "/"))
                sftp.get(remote_path + path_of_asset, local_path +path_of_asset_in_repo)
                #exported_assets_list.insert(tk.END, (local_path +path_of_asset_in_repo).replace("\\", "/"))
            #sftp.get(remote_path + path_of_asset, local_path +path_of_asset_in_repo)
        sftp.close()
        ssh.close()
    except:
        logger.exception('')

servers_frame = tk.Frame(frame)

delete_server_button = tk.Button(servers_frame, 
                        text = "Delete", 
                        background="#ff3313",
                        font="bold",
                        state="disabled",
                        foreground="white",
                        command = delete_server) 
edit_server_button = tk.Button(servers_frame, 
                        text = "Edit", 
                        background="#5512fb",
                        font="bold",
                        state="disabled",
                        foreground="white",
                        command = lambda: server_popup(servers_dropdown.get())) 
is_assets_frame = tk.Frame(frame)
export_button = tk.Button(is_assets_frame, 
                        text = "Export", 
                        background="#1776bf",
                        font="bold",
                        foreground="white",
                        state="disabled",
                        command = export_files) 
selected_server = tk.StringVar(frame)
selected_server.set(None)

placeholder_text = "PackageName.flow:flowService\nPackageName.docs\nPackageName/config/PackageName.cnf"

def set_configs_from_json(config=None):
    global export_button, delete_server_button, edit_server_button, local_path, remote_path, server_ip, server_port, server_ssh_username, server_ssh_password
    if config == None:
        export_button["state"] = "disabled"
        delete_server_button["state"] = "disabled"
        edit_server_button["state"] = "disabled"
        local_path = ""
        remote_path = ""
        server_ip = ""
        server_port = ""
        server_ssh_username = ""
        server_ssh_password = ""
    else:
        export_button["state"] = "normal"
        delete_server_button["state"] = "normal"
        edit_server_button["state"] = "normal"
        local_path = config['local_path'].replace("\\", "/") + '/'
        remote_path = config['remote_path']
        server_ip = config["server_ip"]
        server_port = config["server_port"]
        server_ssh_username = config["server_ssh_username"]
        server_ssh_password = config["server_ssh_password"]

with open(app_data_file, 'r') as file:
    servers_config = json.load(file)
    servers_config_keys = list(servers_config.keys())
    if len(servers_config_keys) > 0:
        selected_server.set(servers_config_keys[0])
        first_config = servers_config[servers_config_keys[0]]
        set_configs_from_json(first_config)



logging.basicConfig(filename='ISExport.log', level=logging.INFO)
logger.info('Started')

def switch_server(event=None):
    global servers_config, servers_config_keys
    set_configs_from_json(servers_config[servers_dropdown.get()] if len(servers_config_keys) > 0 else None)

selected_server.trace("w", switch_server)

def name_to_path(assetName):
    # assetName = is_assets_input.get(1.0, "end-1c") 
    logger.info('assetName: '+assetName)
    if('.' in assetName and '/' not in assetName):
        
        assetNameSplit = assetName.split('.', 1)
        packageName = assetNameSplit[0]
        return packageName + '/ns/' + packageName+ '/' + assetNameSplit[1].replace('.', '/').replace(':', '/')
    else:
        return assetName
    

def delete_local_files(local_dir):
    for filename in os.listdir(local_dir):
        file_path = os.path.join(local_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            logger.info('Failed to delete %s. Reason: %s' % (file_path, e))
def download_files(sftp_client, remote_dir, local_dir):
    global remote_path, local_path

    if not exists_remote(sftp_client, remote_dir):
        return

    if not os.path.exists(local_dir):
        os.mkdir(local_dir)
    else:
        delete_local_files(local_dir)

    for filename in sftp_client.listdir(remote_dir):
        logger.info(filename)
        
        remote_file = remote_dir + filename
        local_file = os.path.join(local_dir, filename)
        
        if stat.S_ISDIR(sftp_client.stat(remote_file).st_mode):
            download_files(sftp_client, remote_file + '/', local_file)
        else:
            logger.info('Exporting remote file: '+ remote_file)
            logger.info('into local file: '+ local_file)
            sftp_client.get(remote_file, local_file)


def exists_remote(sftp_client, path):
    try:
        sftp_client.stat(path)
    except IOError as e:
        if e.errno == errno.ENOENT:
            return False
        raise
    else:
        return True
    

def focus_in_text_box(event):
    if is_assets_input['fg'] == 'Grey':
        is_assets_input['fg'] = 'Black'
        is_assets_input.delete(1.0,tk.END)

def focus_out_text_box(event):
        if len(is_assets_input.get(1.0, "end-1c")) == 0:
            is_assets_input.delete(1.0,tk.END)
            is_assets_input['fg'] = 'Grey'
            is_assets_input.insert(1.0, placeholder_text)
def update_config_file_on_disk():
    global app_data_file, servers_config, servers_config_keys
    with open(app_data_file, 'w') as file:
        json.dump(servers_config, file)
        logger.info("Persisted server configurations!")
        servers_dropdown["values"] = servers_config_keys

def add_server(data, frame):
    global servers_config, servers_dropdown, server_popup_open
    logger.info("add_server:" +data["name_entry"].get())
    if data["name_entry"].get() == "" or data["local_entry"].get() == "" or data["remote_entry"].get() == "" or data["server_ip_entry"].get() == "" or data["server_port_entry"].get() == "" or data["username_entry"].get() == "" or data["password_entry"].get() == "":
        logger.warning("Fill all fields!")
        return
    local_path = data["local_entry"].get()
    remote_path = data["remote_entry"].get()
    if not local_path.endswith("\\"):
        data["local_entry"].delete(0, 'end')
        data["local_entry"].insert(0, local_path+"\\")
    if not remote_path.endswith("/"):
        data["remote_entry"].delete(0, 'end')
        data["remote_entry"].insert(0, remote_path+"/")

    servers_config[data["name_entry"].get()] = {
            "local_path": data["local_entry"].get(),
            "remote_path": data["remote_entry"].get(),
            "server_ip": data["server_ip_entry"].get(),
            "server_port": data["server_port_entry"].get(),
            "server_ssh_username": data["username_entry"].get(),
            "server_ssh_password": data["password_entry"].get()
        }
    is_new_server = False
    if(data["name_entry"].get() not in set(servers_config_keys)):
        servers_config_keys.append(data["name_entry"].get())
        is_new_server=True
        
    update_config_file_on_disk()

    if(is_new_server):
        servers_dropdown.current(len(servers_config_keys) - 1)

    switch_server()

    logger.info("Added server \"{0}\" successfully.".format(servers_dropdown.get()))
    if frame:
        frame.destroy()
    server_popup_open = False

def on_close_server_popup(add_server_top):
    global server_popup_open
    server_popup_open = False
    add_server_top.destroy()
    





# TextBox Creation 
servers_frame.pack(expand=False, fill="both")
add_server_button = tk.Button(servers_frame, 
                        text = "Add Server", 
                        background="#ffff8f",
                        font="bold",
                        foreground="black",
                        command = lambda: server_popup())

servers_dropdown_label = tk.Label(servers_frame, text="Server: ")
servers_dropdown = ttk.Combobox(servers_frame , values=servers_config_keys, width=20,state="readonly")
if len(servers_config_keys) > 0:
    servers_dropdown.current(0) 
servers_dropdown_label.pack(side=tk.LEFT,  fill="y", padx=5, pady=10)
servers_dropdown.pack(side=tk.LEFT,  fill="y", padx=5, pady=10)
servers_dropdown.bind('<<ComboboxSelected>>', switch_server)
edit_server_button.pack(side=tk.LEFT, padx=10, pady=10)
delete_server_button.pack(side=tk.LEFT, pady=10)
add_server_button.pack(side=tk.LEFT, padx=20, pady=10)

is_assets_frame.pack(expand=True, fill="both")
logs_frame = tk.Frame(frame)
logs_frame.pack(expand=True, fill="both")
is_assets_label = tk.Label(is_assets_frame, text="Assets: ")

is_assets_input = tk.Text(is_assets_frame, 
                   height = 5,
                   undo=True,
                   #width = 120
                   )
is_assets_input.bind("<FocusIn>", focus_in_text_box)
is_assets_input.bind("<FocusOut>", focus_out_text_box)

is_assets_input['fg'] = 'Grey'
is_assets_input.insert(1.0, placeholder_text)
scrollbar = tk.Scrollbar(frame)
is_assets_label.pack(side=tk.LEFT,  fill="y", padx=5, pady=10)
is_assets_input.pack(side=tk.LEFT, expand=True, fill="both", padx=5, pady=5)
export_button.pack(side=tk.RIGHT, padx=20, pady=10)
logs_text.pack(side=tk.LEFT, expand=True, fill="both", padx=5, pady=5)

scrollbar.config(command=logs_text.yview)




frame.mainloop() 