import pyshark
import asyncio

capture = pyshark.LiveCapture(interface="wlp2s0mon")

try:
	capture.sniff(timeout=10)

except asyncio.exceptions.TimeoutError:
	print("End of capturing")

print(capture)