# Zoom Decoder

This project decodes encrypted audio content from a pcap recording of a Zoom meeting.

A small caveat for this is that the Meeting Key (MK) must be recovered using Frida.

## Usage

1. Transpile the Frida agent
```bash
cd frida-hook
npm ci
npm run build
```

2. Start Zoom with Frida attached to dump the Meeting Key (MK)
*Note:* Make sure no other Zoom instance is running
```bash
cd frida-hook
uv sync
uv run main.py
```

3. Start capturing a packet trace using a tool of your choice and join the meeting.

4. Save the capture to a .pcap file

5. Quit the Zoom application and locate the most common AES-GCM key in the agent's output. This should be the Meeting Key (MK)

6. Decode the audio using `packet-decoder`
```sh
cd packet-decoder
uv sync
uv run main.py /path/to/capture.pcap AESKEYGOESHERE1234123412341234 /path/to/output.wav
```
