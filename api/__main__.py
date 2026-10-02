import uvicorn
from app.config import settings


def main():
    uvicorn.run("api.app:app",host=settings.api_host,port=settings.api_port,reload=False)


if __name__ == "__main__":
    main()
