#!/usr/bin/env python3
"""
Lightweight proxy server for vlam.ai <-> Mistral Vibe format translation.

This proxy sits between Mistral Vibe and vlam.ai, translating between:
- OpenAI's standard tool calling format (from Mistral Vibe)
- vlam.ai's custom tool format: [TOOL_CALLS]<name>{args} and [TOOL_RESULT]<name>{result}

Usage:
    1. Configure .env file with your VLAM_URL
    2. Run: python proxy.py
    3. Point Mistral Vibe provider URL to: http://localhost:8080
"""

import argparse
import json
import logging
import os
import uuid
from typing import Any, AsyncIterator
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import uvicorn
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load .env file
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

app = FastAPI(title="Vlam.ai Proxy")

# Load configuration from .env
VLAM_URL = os.getenv("VLAM_URL", "https://api.vlam.ai/v1")
VLAM_KEY = os.getenv("VLAM_KEY", "error")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() in ("true", "1", "yes", "on")
MODELS_RESPONSE = os.getenv("MODELS_RESPONSE")

# Validate that VLAM_KEY is set and not the error default or example value
if VLAM_KEY == "error" or VLAM_KEY == "your_api_key_here":
    logger.error("VLAM_KEY environment variable is required but not set.")
    raise ValueError("VLAM_KEY environment variable is required but not set.")

# Global HTTP client for connection pooling
http_client: httpx.AsyncClient | None = None


@app.on_event("startup")
async def startup():
    """Initialize global HTTP client for connection reuse."""
    global http_client
    http_client = httpx.AsyncClient(timeout=300.0, verify=SSL_VERIFY)


@app.on_event("shutdown")
async def shutdown():
    """Close global HTTP client on shutdown."""
    global http_client
    if http_client:
        await http_client.aclose()


def extract_json_object(s: str, start: int) -> tuple[str, int]:
    """
    Extract a complete JSON object starting at position start.

    Handles nested braces correctly by counting bracket depth.
    Returns (json_string, end_position) or ("", start) if no valid JSON found.
    """
    if start >= len(s) or s[start] != '{':
        return "", start

    depth = 0
    i = start
    in_string = False
    escape_next = False

    while i < len(s):
        char = s[i]

        if escape_next:
            escape_next = False
            i += 1
            continue

        if char == '\\' and in_string:
            escape_next = True
            i += 1
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
        elif not in_string:
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return s[start:i+1], i + 1

        i += 1

    return "", start  # Unclosed brace


def parse_tool_calls(content: str) -> list[dict[str, Any]]:
    """
    Parse [TOOL_CALLS] markers from content and extract tool calls.

    Handles nested JSON correctly using balanced bracket matching.
    """
    tool_calls = []
    marker = "[TOOL_CALLS]"
    pos = 0

    while True:
        # Find next [TOOL_CALLS] marker
        marker_pos = content.find(marker, pos)
        if marker_pos == -1:
            break

        # Move past the marker
        name_start = marker_pos + len(marker)

        # Extract tool name (alphanumeric + underscore)
        name_end = name_start
        while name_end < len(content) and (content[name_end].isalnum() or content[name_end] == '_'):
            name_end += 1

        if name_end == name_start:
            # No valid name found, skip this marker
            pos = name_start
            continue

        tool_name = content[name_start:name_end]

        # Extract JSON arguments using balanced bracket matching
        json_str, next_pos = extract_json_object(content, name_end)

        if json_str:
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json_str
                }
            })
            pos = next_pos
        else:
            pos = name_end

    return tool_calls


def vlam_to_openai_message(message: dict[str, Any]) -> dict[str, Any]:
    """
    Convert vlam.ai custom format back to OpenAI format.

    Transforms:
    - [TOOL_CALLS]<name>{args} in content -> tool_calls array
    """
    content = message.get("content", "")

    # Check if this is a tool call in vlam format
    if isinstance(content, str) and "[TOOL_CALLS]" in content:
        tool_calls = parse_tool_calls(content)

        if tool_calls:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": tool_calls
            }

    # Pass through regular messages
    return message


def openai_to_vlam_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert OpenAI tool result message to vlam.ai custom format.

    Transforms:
    - role: tool with content -> role: user with [TOOL_RESULT]<name>{content}
    - role: assistant with tool_calls -> role: assistant with [TOOL_CALLS] format
    - Filters out messages with invalid/missing roles
    """
    role = message.get("role")

    # Filter out messages with no valid role
    if not role:
        return None

    # Check if this is a tool result message (OpenAI format)
    if role == "tool":
        tool_name = message.get("name", "unknown")
        content = message.get("content", "")

        return {
            "role": "user",
            "content": f"[TOOL_RESULT]{tool_name}{{{content}}}"
        }

    # Check if this is an assistant message with tool_calls (OpenAI format)
    if role == "assistant" and message.get("tool_calls"):
        tool_calls = message["tool_calls"]
        tool_calls_str = ""
        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "unknown")
            args = func.get("arguments", "{}")
            tool_calls_str += f"[TOOL_CALLS]{name}{args}"

        return {
            "role": "assistant",
            "content": tool_calls_str
        }

    # Pass through regular messages
    return message


def openai_to_vlam_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert all messages from OpenAI format to vlam.ai format.

    Transforms:
    - role: tool messages -> role: user with [TOOL_RESULT] format
    - role: assistant with tool_calls -> role: assistant with [TOOL_CALLS] format
    - Filters out messages with invalid/missing roles
    """
    converted = [openai_to_vlam_message(msg) for msg in messages]
    return [msg for msg in converted if msg is not None]


def convert_vlam_chunk_to_openai(chunk_data: dict[str, Any]) -> dict[str, Any]:
    """Convert streaming chunk from vlam.ai custom format to OpenAI format."""
    if "choices" not in chunk_data:
        return chunk_data

    for choice in chunk_data["choices"]:
        if "delta" in choice:
            delta = choice["delta"]
            content = delta.get("content", "")

            # Check if content contains vlam's [TOOL_CALLS] format
            if isinstance(content, str) and "[TOOL_CALLS]" in content:
                # Parse tool calls using balanced bracket matching
                tool_calls = parse_tool_calls(content)

                # Add index field for streaming (required by OpenAI streaming format)
                for i, tc in enumerate(tool_calls):
                    tc["index"] = i

                if tool_calls:
                    # Replace content with tool_calls in OpenAI format
                    choice["delta"] = {
                        "role": "assistant",
                        "tool_calls": tool_calls
                    }

    return chunk_data


async def stream_response(upstream_response: httpx.Response) -> AsyncIterator[bytes]:
    """Stream and transform SSE responses from vlam.ai to OpenAI format."""

    buffer = ""
    content_buffer = ""  # Buffer to accumulate content for tool call detection
    last_chunk_template = None  # Store chunk template for final tool_calls emission
    tool_call_detected = False

    async for chunk in upstream_response.aiter_bytes():
        buffer += chunk.decode('utf-8')

        while '\n\n' in buffer:
            line, buffer = buffer.split('\n\n', 1)

            if line.startswith('data: '):
                data_str = line[6:]  # Remove 'data: ' prefix

                if data_str.strip() == '[DONE]':
                    # Before sending [DONE], check if we have buffered tool calls
                    if tool_call_detected and content_buffer and last_chunk_template:
                        tool_calls = parse_tool_calls(content_buffer)
                        if tool_calls:
                            # Add index field for streaming
                            for i, tc in enumerate(tool_calls):
                                tc["index"] = i
                            # Emit tool_calls chunk
                            tool_chunk = last_chunk_template.copy()
                            tool_chunk["choices"] = [{
                                "index": 0,
                                "delta": {
                                    "role": "assistant",
                                    "content": None,
                                    "tool_calls": tool_calls
                                },
                                "finish_reason": "tool_calls"
                            }]
                            yield f'data: {json.dumps(tool_chunk)}\n\n'.encode('utf-8')
                    yield b'data: [DONE]\n\n'
                    continue

                try:
                    data = json.loads(data_str)

                    # Store chunk template for later use
                    if last_chunk_template is None:
                        last_chunk_template = {k: v for k, v in data.items() if k != "choices"}

                    # Accumulate content to detect tool calls
                    if "choices" in data:
                        for choice in data["choices"]:
                            if "delta" in choice:
                                delta = choice["delta"]
                                content = delta.get("content", "")
                                if content:
                                    content_buffer += content
                                    # Check if this looks like a tool call
                                    if "[TOOL_CALLS]" in content_buffer:
                                        tool_call_detected = True

                    # If tool call detected, don't stream the raw content
                    # We'll emit the proper tool_calls format at the end
                    if tool_call_detected:
                        # Send empty deltas to keep connection alive but don't show [TOOL_CALLS] text
                        if "choices" in data:
                            for choice in data["choices"]:
                                if "delta" in choice and choice["delta"].get("content"):
                                    choice["delta"]["content"] = ""

                    # Remove null fields from delta that cause validation errors
                    if "choices" in data:
                        for choice in data["choices"]:
                            if "delta" in choice:
                                delta = choice["delta"]
                                # Remove null values - they cause pydantic validation errors
                                keys_to_remove = [k for k, v in delta.items() if v is None]
                                for k in keys_to_remove:
                                    del delta[k]

                    # Don't emit the finish_reason: stop chunk if we have tool calls
                    # We'll emit finish_reason: tool_calls instead
                    skip_chunk = False
                    if tool_call_detected and "choices" in data:
                        for choice in data["choices"]:
                            if choice.get("finish_reason") == "stop":
                                skip_chunk = True
                                break

                    if not skip_chunk:
                        yield f'data: {json.dumps(data)}\n\n'.encode('utf-8')
                except json.JSONDecodeError:
                    # Pass through invalid JSON as-is
                    yield f'{line}\n\n'.encode('utf-8')
            else:
                # Pass through non-data lines (SSE comments, etc.)
                yield f'{line}\n\n'.encode('utf-8')

    # Discard incomplete buffer data - incomplete SSE events are not useful
    # and could confuse the client
    if buffer.strip():
        logging.warning(f"Discarding incomplete SSE buffer: {buffer[:100]}...")


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def proxy_chat_completions(request: Request):
    """
    Proxy endpoint that translates between Mistral Vibe (OpenAI format) and vlam.ai (custom format).

    Bidirectional conversion:

    Request (Mistral Vibe -> vlam.ai):
    - OpenAI tool role messages -> [TOOL_RESULT]<name>{content} format

    Response (vlam.ai -> Mistral Vibe):
    - [TOOL_CALLS]<name>{args} -> OpenAI tool_calls array
    """
    global http_client

    # Parse incoming request from Mistral Vibe (already in OpenAI format)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return Response(
            content=json.dumps({"error": "Invalid JSON in request body"}),
            media_type="application/json",
            status_code=400
        )

    # Basic request validation
    if not body.get("messages"):
        return Response(
            content=json.dumps({"error": "messages field is required"}),
            media_type="application/json",
            status_code=400
        )

    if not isinstance(body["messages"], list):
        return Response(
            content=json.dumps({"error": "messages must be an array"}),
            media_type="application/json",
            status_code=400
        )

    # Convert request messages from OpenAI format to vlam.ai format
    # This converts tool role messages to [TOOL_RESULT] format
    body["messages"] = openai_to_vlam_messages(body["messages"])

    # Prepare upstream request to vlam.ai
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    headers["authorization"] = f"Bearer {VLAM_KEY}"

    is_streaming = body.get("stream", False)

    # Ensure http_client is available
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=300.0, verify=SSL_VERIFY)

    try:
        if is_streaming:
            # Handle streaming response - use stream() for true streaming
            req = http_client.build_request(
                "POST",
                f"{VLAM_URL}/chat/completions",
                json=body,
                headers=headers,
                timeout=300.0
            )
            upstream_response = await http_client.send(req, stream=True)

            async def streaming_generator():
                try:
                    async for chunk in stream_response(upstream_response):
                        yield chunk
                finally:
                    await upstream_response.aclose()

            return StreamingResponse(
                streaming_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                }
            )
        else:
            # Handle non-streaming response
            upstream_response = await http_client.post(
                f"{VLAM_URL}/chat/completions",
                json=body,
                headers=headers,
            )

            response_data = upstream_response.json()

            # Convert response from vlam custom format to OpenAI format
            if "choices" in response_data:
                for choice in response_data["choices"]:
                    if "message" in choice:
                        # Convert vlam's [TOOL_CALLS] format back to OpenAI tool_calls
                        choice["message"] = vlam_to_openai_message(choice["message"])

            return Response(
                content=json.dumps(response_data),
                media_type="application/json",
                status_code=upstream_response.status_code
            )

    except httpx.RequestError as e:
        return Response(
            content=json.dumps({"error": f"Vlam.ai request failed: {str(e)}"}),
            media_type="application/json",
            status_code=502
        )


@app.get("/v1/models")
@app.get("/models")
async def proxy_models(request: Request):
    """Proxy endpoint to list available models from vlam.ai.
    
    If MODELS_RESPONSE environment variable is set, returns that directly
    without querying the upstream vlam.ai service.
    """
    global http_client

    # Check if we have a configured static response
    if MODELS_RESPONSE:
        logger.info("Returning static models response from MODELS_RESPONSE environment variable")
        return Response(
            content=MODELS_RESPONSE,
            media_type="application/json",
            status_code=200
        )

    # Otherwise, proxy to vlam.ai as usual
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=300.0, verify=SSL_VERIFY)

    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    headers["authorization"] = f"Bearer {VLAM_KEY}"

    try:
        upstream_response = await http_client.get(
            f"{VLAM_URL}/models",
            headers=headers,
            timeout=30.0
        )
        return Response(
            content=upstream_response.content,
            media_type="application/json",
            status_code=upstream_response.status_code
        )
    except httpx.RequestError as e:
        return Response(
            content=json.dumps({"error": f"Vlam.ai request failed: {str(e)}"}),
            media_type="application/json",
            status_code=502
        )


@app.get("/health")
async def health_check(deep: bool = False):
    """
    Health check endpoint.

    Args:
        deep: If True, also check upstream vlam.ai connectivity.
    """
    global http_client

    result = {
        "status": "ok",
        "vlam_url": VLAM_URL,
        "proxy_port": PROXY_PORT,
        "proxy_host": PROXY_HOST,
        "ssl_verify": SSL_VERIFY
    }

    if deep:
        # Ensure http_client is available
        if http_client is None:
            http_client = httpx.AsyncClient(timeout=300.0, verify=SSL_VERIFY)

        try:
            # Try to reach vlam.ai (use a short timeout for health check)
            response = await http_client.get(
                f"{VLAM_URL}/models",
                timeout=5.0
            )
            result["upstream_status"] = "ok" if response.status_code < 500 else "error"
            result["upstream_status_code"] = response.status_code
        except httpx.RequestError as e:
            result["upstream_status"] = "unreachable"
            result["upstream_error"] = str(e)
            result["status"] = "degraded"

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Vlam.ai proxy server - Configuration is read from .env file"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=PROXY_PORT,
        help=f"Port to listen on (default: {PROXY_PORT} from .env)"
    )
    parser.add_argument(
        "--host",
        default=PROXY_HOST,
        help=f"Host to bind to (default: {PROXY_HOST} from .env)"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("🚀 Vlam.ai Proxy Server")
    print("=" * 70)
    print(f"   Proxy listening on:   http://{args.host}:{args.port}")
    print(f"   Forwarding to vlam:   {VLAM_URL}")
    print(f"   Health check:         http://{args.host}:{args.port}/health")
    print("=" * 70)
    print()
    print("📝 Configuration (from .env file):")
    print(f"   VLAM_URL={VLAM_URL}")
    print(f"   PROXY_PORT={PROXY_PORT}")
    print(f"   PROXY_HOST={PROXY_HOST}")
    print()
    print("💡 To use with Mistral Vibe:")
    print(f"   Set provider URL to: http://localhost:{args.port}")
    print("=" * 70)

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
