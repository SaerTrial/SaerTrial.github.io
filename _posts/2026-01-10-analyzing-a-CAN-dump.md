---
title: Analyzing ECU flashing in a CAN dump 
categories:
- automotive security
- ecu flashing
---

I took the training "Hands-on car hacking" in the hardwear.io netherlands 2025. One of CTF challenges is to analyze a CAN dump and extract ECU firmware from UDS messages. 



# What does the CAN dump include?

Here is the part of traffic in the CAN log, which includes timestamp, arbitration ID and payload. The payload can be anything but looks like ISO-TP by first byte.

```
35899.821039792 0x7df b'0210030000000000'
35899.821039792 0x7d8 b'025003aaaaaaaaaa'
35899.821039792 0x7dc b'065003003201f4aa'
35899.83089625 0x79b b'0250030000000000'
35899.83089625 0x7b9 b'065003003201f4aa'
35899.83089625 0x7ce b'0250030000000000'
35899.83089625 0x77e b'025003aaaaaaaaaa'
35899.850885521 0x75d b'065003003201f4aa'
35899.850885521 0x7bf b'065003003201f4aa'
35899.940985313 0x7b1 b'0322f11000000000'
35899.960945 0x7b9 b'102a62f110444e38'
35899.960945 0x7b1 b'3008020000000000'
35899.960945 0x7b9 b'214120414441535f'
35899.97093125 0x7b9 b'2250524b20414e4c'
35899.98089875 0x7b9 b'2320312e30302031'
35899.990896198 0x7b9 b'242e303120393939'
35900.000903282 0x7b9 b'2531302d4c303030'
35900.010905 0x7b9 b'2630aaaaaaaaaaaa'
```

# A Refresher for CAN and ISO-TP
Clearly, CAN has max 8 byte payload, which cannot afford to more data for diagnostics purposes. In order to solve this problem, engineers then introduced ISO-TP. One ISO-TP payload carries multiple CAN frames, allowing UDS to be serviced. 

ISO-TP supports a single frame or multiple frames with flow control. This post only covers multiple frames. For a frame, the first 4 bits represent a type, which could be 0 (single frame), 1 (first frame), 2 (consecutive frame), and 3 (flow control). The following case shows a first frame, where its following 14 bits after type represent the size of payload. The size of payload for this frame is 0x02a. The rest is the part of payload.

```
35899.960945 0x7b9 b'102a62f110444e38'
```


It is clear that the second message sent by the same arbitration ID is a consecutive frame since its type is 2. The 4 bits following type is an index for the frame, starting from 1 and repeating as necessary. See below. 
```
35899.960945 0x7b9 b'214120414441535f'
35899.97093125 0x7b9 b'2250524b20414e4c'
35899.98089875 0x7b9 b'2320312e30302031'
35899.990896198 0x7b9 b'242e303120393939'
35900.000903282 0x7b9 b'2531302d4c303030'
35900.010905 0x7b9 b'2630aaaaaaaaaaaa'
```
The last frame is the index 6. 

So, let ChatGPT to write a ISO-TP decoder as following:
```python
def parse_isotp(can_id, frame_bytes):
    pci = frame_bytes[0]
    ftype = (pci & 0xF0) >> 4
    low = pci & 0x0F

    # ---- Single Frame ----
    if ftype == 0x0:
        length = low
        return frame_bytes[1:1 + length]

    # ---- First Frame ----
    elif ftype == 0x1:
        total_len = (low << 8) | frame_bytes[1]
        sessions[can_id] = {
            "data": bytearray(frame_bytes[2:]),
            "total_len": total_len,
            "next_sn": 1,
        }
        return None

    # ---- Consecutive Frame ----
    elif ftype == 0x2:
        if can_id not in sessions:
            print(f"[WARN] CF without FF for CAN {hex(can_id)}")
            return None

        s = sessions[can_id]
        sn = low

        if sn != s["next_sn"]:
            print(f"[WARN] Bad SN for CAN {hex(can_id)}: got {sn}, expected {s['next_sn']}")
            del sessions[can_id]
            return None

        s["data"].extend(frame_bytes[1:])
        s["next_sn"] = (s["next_sn"] + 1) & 0x0F

        if len(s["data"]) >= s["total_len"]:
            full = bytes(s["data"][:s["total_len"]])
            del sessions[can_id]
            return full

        return None

    # ---- Flow Control ----
    elif ftype == 0x3:
        return None

    else:
        print(f"[WARN] Unknown ISO-TP type: {hex(pci)}")
        return None
```

# What is in the ISO-TP payload?

The payload can be anything. UDS is just the most common thing carried in it. Assume that there is UDS running in the bus, adapt the above script to scan UDS messages in the top-down manner. There are a few arbitration IDs, including 0x7b1, 0x7b9, 0x7bf, etc. I pick one appeared most - 0x7b1 and get the following log, indicating a firmware download to an ECU. 

```
[UDS] ReadDataByIdentifier, 0x22
[UDS] UnknownUDS, 0x20
[UDS] DiagnosticSessionControl, 0x10
[UDS] SecurityAccess, 0x27
[UDS] SecurityAccess, 0x27
[UDS] RoutineControl, 0x31
[UDS] RequestDownload, 0x34
[UDS] TransferData, 0x36
[UDS] TransferData, 0x36
[UDS] TransferData, 0x36
// TransferData repeated many times here
[UDS] RequestTransferExit, 0x37 
[UDS] RoutineControl, 0x31
[UDS] ECUReset, 0x11
```

Improve the script to show more details for each UDS message, since it is quite interesting to know the flashig address and the size of firmware.
```
[UDS] ReadDataByIdentifier, 0x22, DID: f110
[UDS] UnknownUDS, 0x20, 
[UDS] DiagnosticSessionControl, 0x10, ProgrammingSession
[UDS] SecurityAccess, 0x27, security level/key: 11
[UDS] SecurityAccess, 0x27, security level/key: 12462ffba84e61d321
[UDS] RoutineControl, 0x31, subfunc: Start, routine identifier: ff00
[UDS] RequestDownload, 0x34, data_format_identifier: 00, addr: a0080000, size: 000d0ee6
[UDS] TransferData, 0x36, 
[UDS] RequestTransferExit, 0x37, 
[UDS] RoutineControl, 0x31, subfunc: Start, routine identifier: ff01
[UDS] ECUReset, 0x11,
```

Very informative by a given address - a0080000, that seems like a Tricore chip. What else to do is to extract firmawre from payload of UDS TransferData messages and make sure the same size as 0xd0ee6.


# ECU flashing

The above UDS messages indicate a typical ECU flashing process and usually start from entering into ProgrammingSession, solving seed/key UDS security access challenge, performing a likely proprietary routine to prepare flashing, requesting a download, sending firmware in slice, then acknowledging the finish. This process basically follows what I learned from the training as the following picture:

1. Reuqest programming session (SID 0x10)
2. Authenticate (SID 0x27)
3. Request Download (SID 0x34)
4. Transfer Data (SID 0x36)
5. Request Transfer Exit (SID 0x37)
6. Check Dependencies Routine (SID 0x31)

Be aware that when "Request Download" is performed, the application area is erased by bootloader and becomes empty until the payload of "Transfer Data" fills up. The very last step is to validate the downloaded firmware by checksum or others in "Check Dependencies Routine", and place a OK signature before the download area. 









