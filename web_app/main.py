from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import requests

app = FastAPI()

# Directorios
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/resumen_data/")
async def obtener_datos():
    try:
        response = requests.get("http://localhost:8000/resumen/")
        if response.status_code == 200:
            data = response.json()
            # Verificamos que tenga lo que esperamos
            if "valor_mas_frecuente" in data and "conteo_por_clase" in data:
                return data
            else:
                return {"error": "Resumen incompleto o aún no generado."}
        else:
            return {"error": f"Estado HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}