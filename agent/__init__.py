"""Package init: loads .env once, before any submodule reads process environment variables."""
from dotenv import load_dotenv

load_dotenv()
