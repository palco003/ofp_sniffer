"""
    Parser of the OpenFlow 1.3 message
"""
import netaddr
from tcpiplib.parser import *
from tcpiplib.prints import *
from struct import unpack
import of13.packet
import of13.dissector
import of13.prints



# ################## OFPT_HELLO ############################


def parse_hello(msg, packet):

    start = 0
    elements = []

    # Get all Elements
    # Each Element has 0 - N bitmaps
    while len(packet[start:]) > 0:
        # Get element[]
        elem = unpack('!HH', packet[start:start+4])
        element = of13.packet.ofp_hello.ofp_hello_elem_header()
        element.type = elem[0]
        element.length = elem[1]

        bitmaps_list = []
        bitmaps = packet[start+4:start+element.length]
        start_bit = 0
        while len(bitmaps[start_bit:]) > 0:
            bp = unpack('!HH', packet[start_bit:start_bit+4])
            bitmap = of13.packet.ofp_hello.ofp_hello_elem_versionbitmap()
            bitmap.type = bp[0]
            bitmap.length = bp[1]

            bmp = unpack('!L', packet[start_bit+4:])
            bitmap.bitmaps = bmp[0]

            start_bit = start_bit + 4 + bitmap.bitmaps

            bitmap.bitmaps = bin(bitmap.bitmaps)

            bitmaps_list.append(bitmap)
            del bitmap

        element.versionbitmap = bitmaps_list
        start += element.length

        elements.append(element)

        del element

    msg.elements = elements
    return 1


# ################## OFPT_ERROR ############################


def parse_error_msg(msg, packet):
    of_error = packet[0:4]
    ofe = unpack('!HH', of_error)
    ofe_type = ofe[0]
    ofe_code = ofe[1]

    msg.error_type, msg.code = of13.dissector.get_ofp_error(ofe_type, ofe_code)
    return 1


# ################## OFPT_ECHO_REQUEST ############################


def parse_echo_request(msg, packet):
    length = len(packet)
    strg = '!%ss' % length
    msg.data = unpack(strg, packet)

    return 0


# ################## OFPT_ECHO_REPLY ############################


def parse_echo_reply(msg, packet):
    length = len(packet)
    strg = '!%ss' % length
    msg.data = unpack(strg, packet)
    return 0


# ################## OFPT_EXPERIMENTER ############################


def parse_experimenter(msg, packet):
    msg.experimenter = 'To finish this function' + packet
    return 0


# ################## OFPT_FEATURE_REPLY ############################


def _parse_bitmask(bitmask, array):
    size = len(array)
    for i in range(0, size):
        mask = 2**i
        aux = bitmask & mask
        if aux == 0:
            array.remove(mask)
    return array


def _parse_capabilities(capabilities):
    caps = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    return _parse_bitmask(capabilities, caps)


def parse_switch_features(msg, packet):
    of_fres = packet[0:24]
    ofrs = unpack('!8sLBB2sLL', of_fres)
    caps = _parse_capabilities(ofrs[5])

    msg.datapath_id = ofrs[0]
    msg.n_buffers = ofrs[1]
    msg.n_tbls = ofrs[2]
    msg.auxiliary_id = ofrs[3]
    msg.pad = ofrs[4]
    msg.caps = caps
    msg.reserved = ofrs[6]

    return 1


# ########## OFPT_GET_CONFIG_REPLY & OFPT_SET_CONFIG ###############


def parse_switch_config(msg, packet):
    options = unpack('!HH', packet[:4])
    msg.flag = of13.dissector.get_config_flags(options[0])
    msg.miss_send_len = options[1]

    return 1


# ################## OFPT_PACKET_IN ############################


def parse_packet_in(msg, packet):
    ofpi = unpack('!LHBBQ', packet[:16])

    msg.buffer_id = ofpi[0]
    msg.total_len = ofpi[1]
    reason = of13.dissector.get_packet_in_reason(ofpi[2])
    msg.reason = reason
    msg.table_id = ofpi[3]
    msg.cookie = ofpi[4]
    next_pos = _parse_matches(msg, packet, 16)
    msg.pad = unpack('!2s', packet[next_pos:next_pos+2])[0]
    msg.data = parser.process_data(packet, next_pos+2, msg)

    return 0


# ################## OFPT_FLOW_REMOVED ############################


def parse_flow_removed(msg, packet):

    offr = unpack('!QHBBLLHHQQ', packet[:40])

    cookie = offr[0] if offr[0] > 0 else 0

    msg.cookie = '0x' + format(cookie, '02x')
    msg.priority = offr[1]
    msg.reason = of13.dissector.get_flow_removed_reason(offr[2])
    msg.table_id = offr[3]
    msg.duration_sec = offr[4]
    msg.duration_nsec = offr[5]
    msg.idle_timeout = offr[6]
    msg.hard_timeout = offr[7]
    msg.packet_count = offr[8]
    msg.byte_count = offr[9]
    msg.match = _parse_matches(msg, packet, 40)

    return 0


# ################## OFPT_PORT_STATUS ############################


def _parse_phy_config(config):

    confs = [1, 4, 32, 64]
    return _parse_bitmask(config, confs)


def _parse_phy_state(state):

    states = [1, 2, 4]
    return _parse_bitmask(state, states)


def _parse_phy_curr(values):

    confs = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]
    return _parse_bitmask(values, confs)


def _parse_phy_ports(packet):

    phy = unpack('!L4s6s2s16sLLLLLLLL', packet)
    port_id = of13.dissector.get_phy_port_id(phy[0])
    hw_addr = prints.eth_addr(phy[2])
    config = _parse_phy_config(phy[5])
    state = _parse_phy_state(phy[6])
    curr = _parse_phy_curr(phy[7])
    advertised = _parse_phy_curr(phy[8])
    supported = _parse_phy_curr(phy[9])
    peer = _parse_phy_curr(phy[10])
#    curr_speed
#    max_speed

    port = of13.packet.ofp_port()
    port.port_id = port_id
    port.pad = phy[1]
    port.hw_addr = hw_addr
    port.pad2 = phy[3]
    port.name = phy[4]
    port.config = config
    port.state = state
    port.curr = curr
    port.advertised = advertised
    port.supported = supported
    port.peer = peer
#    port.curr_speed = None
#    port.max_speed = None

    return port


def parse_port_status(msg, packet):

    ofps_raw = packet[0:8]
    ofps = unpack('!B7s', ofps_raw)
    reason = of13.dissector.get_port_status_reason(ofps[0])
    msg.reason = reason
    msg.pad = ofps[1]
    msg.desc = _parse_phy_ports(packet[8:64])

    return 0


# ################## OFPT_PACKET_OUT ############################


def parse_packet_out(msg, packet):

    ofpo = unpack('!LLH6s', packet[:16])
    actions = _parse_actions(packet[16:20])
    data = parser.process_data(packet, 20, msg)

    msg.buffer_id = ofpo[0]
    msg.in_port = ofpo[1]
    msg.actions_len = ofpo[2]
    msg.pad = ofpo[3]
    msg.actions = actions
    msg.data = data

    return 0


# ################## OFPT_FLOW_MOD ############################


# def parse_ipv6_extension_header(extensions):
    # still useful?
#    bits = [1, 2, 4, 8, 16, 32, 64, 128, 256]
#    return _parse_bitmask(extensions, bits)

def _parse_action_output(packet, start, a_type, a_length, offset=12):
    # Output has 12 bytes
    raw2 = unpack('!LH6s', packet[start:start + offset])
    action = of13.packet.ofp_action_set_output(a_type, a_length)
    action.port = raw2[0]
    action.max_len = raw2[1]
    action.pad = raw2[2]
    return action, offset


def _parser_action_set_vlan_vid(packet, start, a_type, a_length, offset=4):
    # Set_vlan_vid has 4 bytes
    raw2 = unpack('!H2s', packet[start:start + offset])
    action = of13.packet.ofp_action_set_vlan_vid(a_type, a_length)
    action.vlan_vid = raw2[0]
    action.pad = raw2[1]
    return action, offset


def _parse_actions(packet):

    actions = []
    start = 0

    while len(packet[start:]) > 0:
        raw = unpack('!HH', packet[start:start + 4])
        action_type = raw[0]
        action_length = raw[1]

        start += 4

        action_types = {0: _parse_action_output, 1: _parser_action_set_vlan_vid}

        try:
            action, offset = action_types[action_type](packet, start, action_type, action_length)
        except KeyError:
            return 0

        actions.append(action)
        start += offset

    return actions


def _inst_goto_table(packet, start, instruction):
    raw = unpack('!B3s', packet[start:start+4])
    instruction.table_id = raw[0]
    instruction.pad = raw[1]


def _inst_write_metadata(packet, start, instruction):
    raw = unpack('!4s12s12s', packet[start:start + 28])
    instruction.pad = raw[0]
    instruction.metadata = raw[1]
    instruction.metadata_mask = raw[2]


def _inst_write_apply_clear_actions(packet, instruction):

    raw = unpack('!4s', packet[:4])
    instruction.pad = raw[0]
    instruction.actions = _parse_actions(packet[4:])


def _inst_meter(packet, start, instruction):
    raw = unpack('!L', packet[start:start + 4])
    instruction.meter_id = raw[0]


def _inst_experimenter(packet, start, instruction):
    raw = unpack('!L', packet[start:start + 4])
    instruction.experimenter_id = raw[0]


def _parse_instructions(packet, start):

    instructions = []

    while len(packet[start:]) > 0:

        instruction = unpack('!HH', packet[start:start+4])
        i_type = instruction[0]
        i_len = instruction[1]

        # Call proper instruction
        if i_type == 1:
            instruction = of13.packet.ofp_instruction_go_to(i_type, i_len)
            _inst_goto_table(packet, start, instruction)
        elif i_type == 2:
            instruction = of13.packet.ofp_instruction_write_metadata(i_type, i_len)
            _inst_write_metadata(packet, start, instruction)
        elif i_type in [3, 4, 5]:
            instruction = of13.packet.ofp_instruction_wac_actions(i_type, i_len)
            _inst_write_apply_clear_actions(packet[start + 4:], instruction)
        elif i_type == 6:
            instruction = of13.packet.ofp_instruction_meter(i_type, i_len)
            _inst_meter(packet, start, instruction)
        else:
            instruction = of13.packet.ofp_instruction_experimenter(i_type, i_len)
            _inst_experimenter(packet, start, instruction)

        instructions.append(instruction)
        del instruction
        start = start + i_len

    return instructions


def unpack_oxm_payload(oxm_tlv, packet_oxm_payload):

    payload = of13.packet.ofp_match_oxm_payload()
    len_packet_oxm_content = len(packet_oxm_payload)
    strg = ''

    if oxm_tlv.hasmask == 0:
        if len_packet_oxm_content == 1:
            strg = '!B'
        elif len_packet_oxm_content == 2:
            strg = '!H'
        elif len_packet_oxm_content == 3:
            strg = '!3s'
        elif len_packet_oxm_content == 4:
            strg = '!L'
        elif len_packet_oxm_content == 6:
            strg = '!6s'
        elif len_packet_oxm_content == 8:
            strg = '!Q'
        elif len_packet_oxm_content == 16:
            net, host = unpack('!QQ', packet_oxm_payload)
            ipv6 = ((net << 64) | host)
            payload.value = netaddr.IPAddress(ipv6)

            return payload

        payload.value = unpack(strg, packet_oxm_payload)[0]

    else:
        if len_packet_oxm_content == 2:
            strg = '!BB'
        elif len_packet_oxm_content == 4:
            strg = '!HH'
        elif len_packet_oxm_content == 6:
            strg = '!3s3s'
        elif len_packet_oxm_content == 8:
            strg = '!LL'
        elif len_packet_oxm_content == 12:
            strg = '!6s6s'
        elif len_packet_oxm_content == 16:
            strg = '!QQ'
        elif len_packet_oxm_content == 32:
            net, host, net1, host1 = unpack('!QQQQ', packet_oxm_payload)
            host = (net << 64) | host
            subnet = (net1 << 64) | host1
            payload.value = netaddr.IPAddress(host)
            payload.mask = netaddr.IPAddress(subnet)

            return payload

        payload.value, payload.mask = unpack(strg, packet_oxm_payload)

    return payload


def _parse_matches(match, packet, start):

    match.type, match.length = unpack('!HH', packet[start:start + 4])

    length_oxm = match.length - 4
    match.pad = (match.length + 7)/8*8 - match.length

    start += 4
    oxms = packet[start:start+length_oxm]

    start_2 = 0
    oxm_array = []
    while len(oxms[start_2:]) > 0:
        oxm_raw = unpack('!L', oxms[start_2:start_2 + 4])

        oxm_tlv = of13.packet.ofp_match_oxm_fields()
        oxm_tlv.oxm_class = (oxm_raw[0] >> 16)
        oxm_tlv.field = ((oxm_raw[0] >> 9) & 0x7f)
        oxm_tlv.hasmask = ((oxm_raw[0] >> 8) & 1)
        oxm_tlv.length = (oxm_raw[0] & 0xff)

        packet_oxm_payload = oxms[start_2+4:start_2 + 4 + oxm_tlv.length]

        oxm_tlv.payload = unpack_oxm_payload(oxm_tlv, packet_oxm_payload)

        oxm_array.append(oxm_tlv)

        start_2 = start_2 + 4 + oxm_tlv.length

        del oxm_tlv

    match.oxm_fields = oxm_array

    # Return offset for Instructions
    return start + length_oxm + match.pad


def parse_flow_mod(msg, packet):

    ofmod = unpack('!QQBBHHHLLLH2s', packet[:40])

    cookie = ofmod[0] if ofmod[0] > 0 else 0
    cookie_mask = ofmod[1] if ofmod[1] > 0 else 0

    msg.cookie = '0x' + format(cookie, '02x')
    msg.cookie_mask = '0x' + format(cookie_mask, '02x')
    msg.buffer_id = '0x' + format(ofmod[7], '02x')
    msg.out_port = 4294967040 if ofmod[8] > 4294967040 else ofmod[8]
    msg.table_id = ofmod[2]
    msg.command = ofmod[3]
    msg.idle_timeout = ofmod[4]
    msg.hard_timeout = ofmod[5]
    msg.priority = ofmod[6]
    msg.out_group = ofmod[9]
    msg.flags = ofmod[10]
    msg.pad = ofmod[11]

    instructions_start = _parse_matches(msg.match, packet, 40)

    msg.instructions = _parse_instructions(packet, instructions_start)

    return 1


# ################## OFPT_GROUP_MOD ############################


def _parse_buckets(packet):

    ofpb = unpack('!HHLL4s', packet[:16])
    actions = _parse_actions(packet[16:20])

    bucket = of13.packet.ofp_bucket()
    bucket.len = ofpb[0]
    bucket.weight = ofpb[1]
    bucket.watch_port = ofpb[2]
    bucket.watch_group = ofpb[3]
    bucket.pad = ofpb[3]
    bucket.actions = actions

    return bucket


def parse_group_mod(msg, packet):

    ofgm = unpack('!HBBL', packet[:8])
    command = of13.dissector.get_group_mod_command(ofgm[0])
    group_type = of13.dissector.get_group_mod_type(ofgm[1])

    msg.command = command
    msg.group_type = group_type
    msg.pad = ofgm[2]
    msg.group_id = ofgm[3]
    msg.buckets = _parse_buckets(packet[8:])

    return 0


# ################## OFPT_PORT_MOD ############################


def parse_port_mod(msg, packet):


    msg.port_no = None  # 4 bytes
    msg.pad = None  # 4 Bytes
    msg.hw_addr = None  # 6 bytes
    msg.pad2 = None  # 2 Bytes
    msg.config = None  # 4 bytes
    msg.mask = None  # 4 bytes
    msg.advertise = None  # 4 bytes - bitmap of OFPPF_*
    msg.pad3 = None  # 4 Bytes
    return 0


# ################## OFPT_TABLE_MOD ############################


def parse_table_mod(msg, packet):

    oftm = unpack('!B3sL', packet)
    config = of13.dissector.get_table_config(oftm[3])

    msg.table_id = oftm[0]
    msg.pad = oftm[1]
    msg.config = config
    return 0


# ################## OFPT_MULTIPART_REQUEST ############################



def parse_multipart_request(msg, packet):
    ofm_req = unpack('!HH4s', packet[:8])

    flags = of13.dissector.get_multipart_request_flags(ofm_req[1])

    msg.stat_type = ofm_req[0]
    msg.flags = flags
    msg.pad = ofm_req[2]

    if msg.stat_type in [0, 3, 7, 8, 11, 13]:
        pass

    # Flow
    elif msg.stat_type == 1:
        of_flow = unpack('!B3sLL4sQQ', packet[8:32])
        table_id = of_flow[0]
        pad = of_flow[1]
        out_port = of_flow[2]
        out_group = of_flow[3]
        pad2 = of_flow[4]
        cookie = of_flow[5]
        cookie_mask = of_flow[6]
        match = _parse_matches(msg, packet, 32)
        msg.instantiate(table_id, pad, out_port, out_group, pad2, cookie, cookie_mask, match)

    # Aggregate
    elif msg.stat_type == 2:
        of_agg = unpack('!B3sLL4sQQ', packet[8:32])
        table_id = of_agg[0]
        pad = of_agg[1]
        out_port = of_agg[2]
        out_group = of_agg[3]
        pad2 = of_agg[4]
        cookie = of_agg[5]
        cookie_mask = of_agg[6]
        match = _parse_matches(msg, packet, 32)
        msg.instantiate(table_id, pad, out_port, out_group, pad2, cookie, cookie_mask, match)

    # Port
    elif msg.stat_type == 4:
        of_port = unpack('!L4s', packet[8:16])
        port_no = of_port[0]
        pad = of_port[1]
        msg.instantiate(port_no, pad)

    # Queue
    elif msg.stat_type == 5:
        of_queue = unpack('!LL', packet[8:16])
        port_no = of_queue[0]
        queue_id = of_queue[1]
        msg.instantiate(port_no, queue_id)

    # Group
    elif msg.stat_type == 6:
        of_group = unpack('!L4s', packet[8:16])
        group_id = of_group[0]
        pad = of_group[1]
        msg.instantiate(group_id, pad)

    # Meter
    elif msg.stat_type == 9:
        of_meter = unpack('!L4s', packet[8:16])
        meter_id = of_meter[0]
        pad = of_meter[1]
        msg.instantiate(meter_id, pad)

    # Meter config
    elif msg.stat_type == 10:
        of_meter_config = unpack('!L4s', packet[8:16])
        meter_id = of_meter_config[0]
        pad = of_meter_config[1]
        msg.instantiate(meter_id, pad)

    # Table features
    elif msg.stat_type == 12:
        of_table = unpack('!HB5sLQQLL', packet[8:48])
        length = of_table[0]
        table_id = of_table[1]
        pad = of_table[2]
        name = of_table[3]
        metadata_match = of_table[4]
        metadata_write = of_table[5]
        config = of_table[6]
        max_entries = of_table[7]
        msg.instantiate(length, table_id, pad, name, metadata_match, metadata_write, config, max_entries)

    # Experimenter
    elif msg.stat_type == 65535:
        of_exp = unpack('!LL', packet[8:16])
        experimenter = of_exp[0]
        exp_type = of_exp[1]
        msg.instantiate(experimenter, exp_type)

    else:
        print 'StatReq: Unknown Type: %s' % msg.stat_type

    return 0


# ################## OFPT_MULTIPART_REPLY ############################


def parse_multipart_reply(msg, packet):
    ofm_rep = unpack('!HH4s', packet[0:8])

    flags = of13.dissector.get_multipart_reply_flags(ofm_rep[1])

    msg.stat_type = ofm_rep[0]
    msg.flags = flags
    msg.pad = ofm_rep[2]
    msg.body = None  # content to be instantiated
    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REQUEST ############################


def parse_queue_get_config_request(msg, packet):

    ofq_req = unpack('!L4s', packet[0:8])

    msg.port = ofq_req[0]
    msg.pad = ofq_req[1]

    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REPLY ############################

def _parse_queues(packet):

    of_queue = unpack('!LLH6s', packet[:16])
    queue = of13.packet.ofp_packet_queue()
    queues = []

    queue.queue_id = of_queue[0]
    queue.port = of_queue[1]
    queue.length = of_queue[2]
    queue.pad = of_queue[3]

    queues.append(queue)
    return queues

def parse_queue_get_config_reply(msg, packet):

    ofq_res = unpack("!L4s", packet[0:8])

    msg.port = ofq_res[0]
    msg.pad = ofq_res[1]
    msg.queues = _parse_queues(packet[8:])
    return 0


# ########## OFPT_ROLE_REQUEST & OFPT_ROLE_REPLY ###############


def parse_role(msg, packet):
    ofr = unpack('!L4sQ', packet[0:16])
    role = of13.dissector.get_controller_role(ofr[0])

    msg.role = role
    msg.pad = ofr[1]
    msg.generation_id = ofr[2]

    #if role value is master or slave switch must validate generation_id
    #if validation fails, switch must discard request and return OFPET_ROLE_REQUEST_FAILED
    #and code OFPRRFC_STALE

    return 0


# ########### OFPT_GET_ASYNC_REPLY & OFPT_SET_ASYNC #####################


def parse_async_config(msg, packet):
    ofac = unpack('!QQQ', packet[0:24])
    packet_in_mask = unpack('!LL', ofac[0])
    port_status_mask = unpack('!LL', ofac[1])
    flow_removed_mask = unpack('!LL', ofac[2])

    msg.packet_in_mask = packet_in_mask
    msg.port_status_mask = port_status_mask
    msg.flow_removed_mask = flow_removed_mask

    return 0


# ################## OFPT_METER_MOD ############################


def parse_meter_mod(msg, packet):

    ofmm = unpack('!HHL', packet[0:8])
    command = of13.dissector.get_meter_command(ofmm[0])
    flags = of13.dissector.get_meter_flags(ofmm[1])
    meter_id = of13.dissector.get_meter(ofmm[2])

    msg.command = command
    msg.flags = flags
    msg.meter_id = meter_id
    msg.bands = []  # class ofp_meter_band_header

    return 0
