import os
import sys
from dotenv import load_dotenv
from langchain_google_vertexai import ChatVertexAI

def verify_vertex_ai():
    load_dotenv()
    
    vertex_use = os.getenv("VITE_GOOGLE_GENAI_USE_VERTEXAI", "false").lower() == "true"
    project = os.getenv("VITE_GOOGLE_CLOUD_PROJECT")
    location = os.getenv("VITE_GOOGLE_CLOUD_LOCATION")
    model = os.getenv("VITE_MODEL")
    creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    
    print("--- Vertex AI Verification ---")
    print(f"Use Vertex AI: {vertex_use}")
    print(f"Project: {project}")
    print(f"Location: {location}")
    print(f"Model: {model}")
    print(f"Credentials Path: {creds}")
    
    if not vertex_use:
        print("❌ VITE_GOOGLE_GENAI_USE_VERTEXAI is not set to true in .env")
        return

    if not all([project, location, model, creds]):
        print("❌ Missing one or more required environment variables in .env")
        return

    if not os.path.exists(creds):
        print(f"⚠️ Warning: Credentials file not found at {creds}")
        print("   If you are on Render, this is expected if the path is /etc/secrets/...")
    
    try:
        print("\nAttempting to initialize ChatVertexAI...")
        llm = ChatVertexAI(
            model=model,
            project=project,
            location=location,
            temperature=0.0
        )
        print("✅ ChatVertexAI initialized successfully!")
        
        # Uncomment below to test actual connectivity if you have internet access
        # response = llm.invoke("Say hello")
        # print(f"Response: {response.content}")
        
    except Exception as e:
        print(f"❌ Initialization failed: {e}")

if __name__ == "__main__":
    verify_vertex_ai()
