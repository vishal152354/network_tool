# main.py

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
import os
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
templates = Jinja2Templates(directory="template")

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
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
        permissions_data.append({
            "Folder Path": folder_path,
            "Principal": "N/A",
            "Type": "Error",
            "Permissions": f"Could not access permissions: {e}"
        })

    return permissions_data


def get_subfolders_walk(parent_folder):
    """Finds immediate subfolders. Returns empty list on error."""
    try:
        dirpath, dirnames, filenames = next(os.walk(parent_folder))
        return [os.path.join(dirpath, name) for name in dirnames]
    except (StopIteration, FileNotFoundError, PermissionError) as e:
        logger.error(f"Error accessing subfolders in '{parent_folder}': {e}")
        return []

def write_permissions_to_csv(data_list):
    """Writes a list of permission dictionaries to a CSV file in the 'reports' directory."""
    if not data_list:
        return None

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_path = os.path.join(REPORTS_DIR, f"permissions_report_{timestamp}.csv")
    
    headers = ["Folder Path", "Principal", "Type", "Permissions"]
    
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data_list)
        logger.info(f"Successfully generated report: {file_path}")
        return os.path.basename(file_path)
    except Exception as e:
        logger.error(f"Failed to write CSV file: {e}")
        return None

# --- FastAPI Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def serve_login_page(request: Request):
    """Serves the login page as the root."""
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serves the main dashboard page."""
    return templates.TemplateResponse("index.html", {"request": request})
@app.post("/logout",response_class=HTMLResponse)
async def Leave_page(request:Request):
    return templates.TemplateResponse("login.html",{"request": request} )
@app.post("/submit_link")
async def submit_link(request: Request):
    data = await request.json()
    link = data.get("link")
    
    if not link or not os.path.exists(link):
        raise HTTPException(status_code=400, detail="===Not authorized to open the folder===")

    logger.info(f"Processing permissions for: {link}")

    all_permissions = []
    all_permissions.extend(get_folder_permissions(link))
    subfolders_list = get_subfolders_walk(link)
    for folder in subfolders_list:
        all_permissions.extend(get_folder_permissions(folder))
    
    if not all_permissions:
         raise HTTPException(status_code=500, detail="Could not retrieve any permission data.")

    report_filename = write_permissions_to_csv(all_permissions)

    if report_filename:
        return JSONResponse({
            "message": "Report generated successfully.", 
            "filename": report_filename,
            "data": all_permissions  
        })
    else:
        raise HTTPException(status_code=500, detail="Failed to generate the report file.")

@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(path=file_path, media_type='text/csv', filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found.")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
