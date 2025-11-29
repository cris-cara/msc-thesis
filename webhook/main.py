import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Text(BaseModel):
    text: str

@app.post("/write")
async def write_to_file(payload: Text):
    print(payload)
    # prende il campo "text" dal JSON
    content = payload.text

    file_path = "output.txt"
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(content + "\n")

    return {"status": "ok", "written": content}

@app.get("/read")
async def read_from_file():
    file_path = "output.txt"
    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()

    return {"status": "ok", "data": data}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
