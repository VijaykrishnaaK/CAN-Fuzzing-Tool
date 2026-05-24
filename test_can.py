import can

bus = can.interface.Bus(channel='vcan0', interface='socketcan')

msg = can.Message(arbitration_id=0x123, data=[0xDE, 0xAD, 0xBE, 0xEF], is_extended_id=False)

bus.send(msg)

print("Message sent!")

bus.shutdown()   # ✅ clean exit
