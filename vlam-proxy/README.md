# Vlam.ai Proxy voor Mistral Vibe opencode

Een lightweight, standalone Python proxy die Mistral Vibe laat werken met vlam.ai door automatisch format conversie te doen.

## 🎯 Wat doet deze proxy?

De proxy zit tussen **Mistral Vibe** en **vlam.ai** en vertaalt automatisch tussen twee formats:

```
Mistral Vibe (OpenAI format) ←→ Proxy ←→ vlam.ai (custom format)
```

### Vlam.ai custom format
```
[TOOL_CALLS]tool_name{"arg": "value"}
[TOOL_RESULT]tool_name{result text}
```

### OpenAI format (wat Mistral Vibe gebruikt)
```json
{
  "tool_calls": [
    {
      "id": "call_123",
      "function": {
        "name": "tool_name",
        "arguments": "{\"arg\": \"value\"}"
      }
    }
  ]
}
```

## 🚀 Quick Start

### Stap 1: Configureer de proxy

```bash
cd /Users/<username>/git/vlam-proxy

# Kopieer .env.example naar .env
cp .env.example .env

# Edit .env en zet je vlam.ai URL
nano .env
```

In `.env`:
```bash
VLAM_URL=https://api.vlam.ai/v1
VLAM_KEY=your-vlam-api-key
PROXY_PORT=8080
PROXY_HOST=localhost
```

### Stap 2: Installeer dependencies

```bash
pip install -r requirements.txt
```

### Stap 3: Start de proxy

```bash
python proxy.py
```

Je ziet:
```
======================================================================
🚀 Vlam.ai Proxy Server
======================================================================
   Proxy listening on:   http://localhost:8080
   Forwarding to vlam:   https://api.vlam.ai/v1
   Health check:         http://localhost:8080/health
======================================================================

📝 Configuration (from .env file):
   VLAM_URL=https://api.vlam.ai/v1
   VLAM_KEY=your-vlam-api-key
   PROXY_PORT=8080
   PROXY_HOST=localhost

💡 To use with Mistral Vibe:
   Set provider URL to: http://localhost:8080
======================================================================
```

### Stap 4: Configureer Mistral Vibe

In je Mistral Vibe configuratie, zet de provider URL naar de proxy:

**Via config bestand** (`~/.vibe/config.toml` of project config):
```
[[providers]]
name = "vlam.ai"
api_base = "http://localhost:8080"
api_style = "openai"
backend = "generic"
reasoning_field_name = "reasoning_content"

[[models]]
name = "ubiops-deployment/ocw-ictswh-mistralmedium-flexibel//chat-model"
provider = "vlam.ai"
alias = "ocw-ictswh-mistralmedium-flexibel"
temperature = 0.2
input_price = 0
output_price = 0
```
In je opencode configuratie, zet de provider URL naar de proxy:

**Via config bestand** (`C:\Users\<user>\.config\opencode.json` of project config):
```
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "vlamai": {
      "name": "vlamai",
      "id": "vlamai",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "http://localhost:8080" 
      },
      "models": {
        "ubiops-deployment/ocw-ictswh-mistralmedium-flexibel//chat-model": {
          "name": "ocw-ictswh-mistralmedium-flexibel",
          "id": "ubiops-deployment/ocw-ictswh-mistralmedium-flexibel//chat-model"
        }
      }
    }
  },
  "model": "vlamai/ubiops-deployment/ocw-ictswh-mistralmedium-flexibel//chat-model"
}
```

### ✅ Klaar!

Nu werkt Mistral Vibe naadloos met vlam.ai via de proxy!

## 📁 Bestanden

```
vlam-proxy/
├── proxy.py              # Main proxy server
├── requirements.txt      # Python dependencies
├── .env                 # Jouw configuratie (git ignored)
├── .env.example         # Template voor configuratie
├── .gitignore          # Git ignore rules
└── README.md           # Deze file
```

## ⚙️ Configuratie

### .env bestand

| Variabele | Beschrijving                                      | Default                  |
|-----------|---------------------------------------------------|--------------------------|
| `VLAM_URL` | De URL van je vlam.ai endpoint                    | `https://api.vlam.ai/v1` |
| `VLAM_KEY` | **Vereist** Je vlam.ai API key                    | **Geen default**         |
| `PROXY_PORT` | Poort waarop de proxy luistert                    | `8080`                   |
| `PROXY_HOST` | Host om te binden                                 | `localhost`              |
| `SSL_VERIFY` | Of HTTPS certificaten moeten worden geverifieerd  | `true`                   |
| `MODELS_RESPONSE` | Een vaste json response voor het /models endpoint | **Geen default**         |

### SSL_VERIFY configuratie

De `SSL_VERIFY` optie stelt je in om HTTPS certificaatverificatie in of uit te schakelen:

- **`SSL_VERIFY=true`** (standaard): Certificaten worden geverifieerd. Dit is veilig en aanbevolen voor productiegebruik.
- **`SSL_VERIFY=false`**: Certificaatverificatie wordt uitgeschakeld. Gebruik dit alleen in testomgevingen of corporate netwerken waar self-signed certificaten in de certificaatketen worden gebruikt (bijvoorbeeld bij HTTPS inspectie).

**Waarschuwing**: Uitschakelen van certificaatverificatie maakt de verbinding kwetsbaar voor man-in-the-middle aanvallen. Gebruik dit alleen als het echt nodig is.

### Command-line overrides

Je kunt de .env settings overriden via command-line:

```bash
python proxy.py --port 9000 --host 127.0.0.1
```

## 🔍 Testen

### Health check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "ok",
  "vlam_url": "https://api.vlam.ai/v1",
  "proxy_port": 8080,
  "proxy_host": "localhost",
  "ssl_verify": true
}
```

### Test met curl

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-vlam-api-key" \
  -d '{
    "model": "mistral-large-latest",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

## 🎬 Complete workflow

```
┌──────────────────────────────────────────────────────────────┐
│                      Complete Flow                            │
└──────────────────────────────────────────────────────────────┘

1. User → Mistral Vibe
   "Use the calculator tool"

2. Mistral Vibe → Proxy (OpenAI format)
   {
     "messages": [...],
     "tools": [{"type": "function", "function": {...}}]
   }

3. Proxy → vlam.ai (OpenAI format, doorgestuurd)
   Same OpenAI format

4. vlam.ai → Proxy (custom format)
   {
     "choices": [{
       "message": {
         "role": "assistant",
         "content": "[TOOL_CALLS]calculator{\"op\":\"add\",\"x\":1,\"y\":2}"
       }
     }]
   }

5. Proxy → Mistral Vibe (OpenAI format, geconverteerd!)
   {
     "choices": [{
       "message": {
         "role": "assistant",
         "tool_calls": [{
           "id": "call_0",
           "type": "function",
           "function": {
             "name": "calculator",
             "arguments": "{\"op\":\"add\",\"x\":1,\"y\":2}"
           }
         }]
       }
     }]
   }

6. Mistral Vibe executes tool and continues conversation ✅
```

## 📊 Performance

- **Latency overhead**: ~1-5ms per request
- **Streaming**: Real-time, geen buffering
- **Memory**: Minimal footprint
- **Concurrent requests**: Async I/O, geen bottleneck

## 🔒 Security

- API keys worden **nooit** gelogd
- Proxy doet alleen format conversie, geen data opslag
- Draai als dedicated user (niet root)

## 🛠️ Development

### Structuur

```python
# Key functies in proxy.py:

vlam_to_openai_message()     # Convert vlam [TOOL_CALLS] → OpenAI tool_calls
openai_to_vlam_message()     # Convert OpenAI tool_calls → vlam [TOOL_CALLS]
vlam_to_openai_messages()    # Convert vlam [TOOL_RESULT] → OpenAI tool role
convert_vlam_chunk_to_openai()  # Streaming chunk conversie
```

### Logging toevoegen

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# In proxy.py functies:
logger.debug(f"Converting message: {message}")
```

### Virtual environment (aanbevolen)

```bash
# Maak venv
python -m venv venv

# Activeer
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Installeer dependencies
pip install -r requirements.txt

# Run proxy
python proxy.py
```

