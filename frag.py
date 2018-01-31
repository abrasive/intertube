def fragment(packet, mtu):
    if packet[12:14] != "\x08\x00":
        # not IP, cannot fragment
        return []

    ip = packet[14:]

    hdr_len = 4 * (ip[0] & 0xf)
    payload_len = len(ip) - hdr_len
    payload = ip[hdr_len:]

    flags = ip[6]
    if flags & 0x40:   # DF
        return []

    max_payload = mtu - 14 - hdr_len
    num_frags = (payload_len / max_payload) + 1

    frags = []

    for i in range(num_frags):
        offset = i*max_payload
        end = (i+1)*max_payload
        frag_payload = payload[offset:end]
        frag_header = bytearray(ip[:hdr_len])

        if i < num_frags - 1:   # More Fragments
            offset |= 0x8000

        frag_header[6] = offset >> 8
        frag_header[7] = offset & 0xff
        frags.append(frag_header + frag_payload)

    return frags
