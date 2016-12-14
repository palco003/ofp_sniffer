import gen.proxies

def process_data(packet, start, msg):
    """
        This function aims to dissect PacketIn and PacketOut data
        It assumes it is
            Ethernet [vlan] (BDDP|LLDP|ARP|IP) [TCP|UDP]
    Args:
        packet: class OFMessage
        start: offset
        msg:
    Returns:
        payload: array with all classes
    """
    payload = []
    # Ethernet
    eth = packet.Ethernet()
    eth.parse(packet[start:start + 14], 1)
    payload.append(eth)

    # VLAN or not - ETYPE 0x8100 or 33024
    etype = '0x0000'

    start += 14
    if eth.protocol in [33024]:
        """
            Frame has VLAN
        """
        vlan = packet.VLAN()
        vlan.parse(packet[start:start + 4])
        payload.append(vlan)
        etype = vlan.protocol
        start += 4
    else:
        etype = eth.protocol

    # LLDP - ETYPE 0x88CC or 35020 or BBDP - ETYPE 0x8942 or 35138
    if etype in [35020, 35138]:
        lldp = packet.LLDP()
        try:
            lldp.parse(packet[start:])
        except:
            pass
        if not isinstance(lldp, packet.LLDP):
            lldp.c_id = 0
        else:
            if msg.type is 13:
                gen.proxies.save_dpid(lldp)
        payload.append(lldp)
        return payload

    # IP - ETYPE 0x800 or 2048
    if etype in [2048]:
        ip = packet.IP()
        ip.parse(packet, start)
        payload.append(ip)
        if ip.protocol is 6:
            tcp = packet.TCP()
            tcp.parse(packet, start + ip.length)
            payload.append(tcp)
        return payload

    # ARP - ETYPE 0x806 or 2054
    if etype in [2054]:
        arp = packet.ARP()
        arp.parse(packet[start:])
        payload.append(arp)
        return payload

    return payload