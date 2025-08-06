# main.py

from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
import os
import subprocess
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
import win32security
import ntsecuritycon as con
import csv
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
templates = Jinja2Templates(directory="template") # Make sure you have a 'templates' folder

# --- Create a directory for reports ---
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- REFACTORED FUNCTIONS ---

def get_folder_permissions(folder_path):
    """
    Retrieves the Access Control Entries (ACEs) for a given folder path
    and returns them as a list of dictionaries.
    """
    permissions_data = []
    if not os.path.exists(folder_path):
        logger.error(f"Path not found: {folder_path}")
        return []

    try:
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        if not dacl:
            return []

        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            try:
                sid = ace[2]
                user_name, domain, user_type = win32security.LookupAccountSid(None, sid)
                principal = f"{domain}\\{user_name}"
            except Exception:
                principal = str(sid)

            access_mask = ace[1]
            ace_type = "Allow" if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE else "Deny"

            # Map access mask to human-readable permissions
            perms_list = []
            if (access_mask & con.FILE_ALL_ACCESS) == con.FILE_ALL_ACCESS:
                perms_list = ["Full Control"]
            else:
                if (access_mask & con.FILE_GENERIC_READ): perms_list.append("Read")
                if (access_mask & con.FILE_GENERIC_WRITE): perms_list.append("Write")
                if (access_mask & con.FILE_GENERIC_EXECUTE): perms_list.append("Execute")
                if (access_mask & con.DELETE): perms_list.append("Delete")
            
            if not perms_list:
                perms_list.append(f"Special (Mask: {access_mask})")

            permissions_data.append({
                "Folder Path": folder_path,
                "Principal": principal,
                "Type": ace_type,
                "Permissions": ', '.join(perms_list)
            })
            
    except Exception as e:
        logger.error(f"Could not get permissions for {folder_path}: {e}")
        # Add an entry to indicate failure for this folder
        permissions_data.append({
            "Folder Path": folder_path,
            "Principal": "N/A",
            "Type": "Error",
            "Permissions": f"Could not access permissions: {e}"
        })

    return permissions_data


def get_subfolders_walk(parent_folder):
    """
    Finds immediate subfolders. Returns empty list on error.
    """
    try:
        dirpath, dirnames, filenames = next(os.walk(parent_folder))
        return [os.path.join(dirpath, name) for name in dirnames]
    except (StopIteration, FileNotFoundError, PermissionError) as e:
        logger.error(f"Error accessing subfolders in '{parent_folder}': {e}")
        return []

def write_permissions_to_csv(data_list):
    """
    Writes a list of permission dictionaries to a CSV file in the 'reports' directory.
    """
    if not data_list:
        return None

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_path = os.path.join(REPORTS_DIR, f"permissions_report_{timestamp}.csv")
    
    # Define headers explicitly to control order
    headers = ["Folder Path", "Principal", "Type", "Permissions"]
    
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data_list)
        logger.info(f"Successfully generated report: {file_path}")
        return os.path.basename(file_path) # Return only the filename
    except Exception as e:
        logger.error(f"Failed to write CSV file: {e}")
        return None

# --- FastAPI Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Renders the main HTML page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/submit_link")
async def submit_link(request: Request):
    """Receives a path, processes permissions, and returns a CSV filename."""
    data = await request.json()
    link = data.get("link")
    
    if not link or not os.path.exists(link):
        raise HTTPException(status_code=400, detail="Invalid or non-existent path provided.")

    logger.info(f"Processing permissions for: {link}")

    # Aggregate all permissions data
    all_permissions = []

    # Get permissions for the parent folder
    all_permissions.extend(get_folder_permissions(link))

    # Get permissions for immediate subfolders
    subfolders_list = get_subfolders_walk(link)
    for folder in subfolders_list:
        all_permissions.extend(get_folder_permissions(folder))
    
    if not all_permissions:
         raise HTTPException(status_code=500, detail="Could not retrieve any permission data.")

    # Write data to CSV and get the filename
    report_filename = write_permissions_to_csv(all_permissions)

    if report_filename:
        return JSONResponse({
            "message": "Report generated successfully.", 
            "filename": report_filename
        })
    else:
        raise HTTPException(status_code=500, detail="Failed to generate the report file.")

@app.get("/download/{filename}")
async def download_file(filename: str):
    """Serves the generated CSV file for download."""
    file_path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(path=file_path, media_type='text/csv', filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found.")

# --- Uvicorn Runner ---
if __name__ == "__main__":
    # Assumes your script is named 'main.py'
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)