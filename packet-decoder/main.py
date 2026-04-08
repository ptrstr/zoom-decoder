import sys
import wave

import scapy.utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyogg import OpusDecoder
from scapy.layers.inet import UDP
from scapy.layers.rtp import RTP
from scapy.packet import Raw


def log(*args):
    print("[*]", *args, file=sys.stderr)


def extract_audio(pcap_path: str, key: str, out_file: str):
    aes_gcm = AESGCM(bytes.fromhex(key))

    log("Loading pcap")
    packets = scapy.utils.rdpcap(pcap_path)

    log("Getting all Zoom packets")
    zoom_packets: list[UDP] = [
        p[UDP] for p in packets.filter(lambda x: UDP in x and x[UDP].sport == 8801)
    ]

    log(f"Found {len(zoom_packets)}. Filtering for RTP")
    rtp_packets: list[RTP] = []
    for p in zoom_packets:
        raw = p.payload.getlayer(Raw)
        if raw is None or raw.load[0] != 0x05 or len(raw.load) < 27:
            continue

        raw = raw.load
        try:
            rtp = RTP(raw[27:])
            if rtp.version != 2 or rtp.payload_type != 116:
                continue

            rtp_packets.append(rtp)
        except Exception:
            pass

    log(f"Found {len(rtp_packets)} RTP packets")
    samples = []
    for p in rtp_packets:
        payload = p.payload.load

        iv = payload[3 : 3 + 12]
        encrypted = payload[3 + 13 : -16]
        tag = payload[-16:]

        decrypted = aes_gcm.decrypt(iv, encrypted + tag, None)

        assert len(decrypted) == int.from_bytes(payload[:2])

        samples.append(decrypted)

    log("Decoding audio")
    wave_write = wave.open(out_file, "wb")
    wave_write.setnchannels(1)
    wave_write.setsampwidth(2)
    wave_write.setframerate(16000)

    opus_decoder = OpusDecoder()
    opus_decoder.set_channels(1)
    opus_decoder.set_sampling_frequency(16000)

    for s in samples:
        decoded_pcm = opus_decoder.decode(bytearray(b"\x68" + s[1:]))
        wave_write.writeframes(decoded_pcm)


def main(argv):
    if len(argv) != 4:
        print("Usage: python main.py <pcap_file> <aes_key> <output.wav>")
        return

    extract_audio(argv[1], argv[2], argv[3])


if __name__ == "__main__":
    main(sys.argv)
