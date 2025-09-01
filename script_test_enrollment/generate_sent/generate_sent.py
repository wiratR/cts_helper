#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, configparser, os, sys, uuid, datetime as dt, base64, re, io
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

NS = {
    "dmb": "http://www.thales.dc/DeviceMessageBatch",
    "dtf": "http://www.thales.dc/DeviceTransactionFiles",
    "dtt": "http://www.thales.dc/TicketingTypes",
    "dsi": "http://www.w3.org/2000/09/xmldsig#",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}
def qname(prefix, local): return etree.QName(NS[prefix], local)
def iso8601_now_z(): return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def iso8601_now_offset(): return dt.datetime.utcnow().replace(microsecond=0, tzinfo=dt.timezone.utc).isoformat()
def get_str(cfg, sec, key, default=""): 
    try: return cfg.get(sec, key)
    except Exception: return default
def get_int(cfg, sec, key, default=0):
    try: return cfg.getint(sec, key)
    except Exception:
        v = get_str(cfg, sec, key, None)
        return int(v) if v not in (None, "") else default
def get_uuid(cfg, sec, key, default_new=True):
    v = get_str(cfg, sec, key, "")
    if v.strip(): return v.strip()
    return str(uuid.uuid4()) if default_new else ""
def parse_emv_tags(cfg, sec="payment_card.emv_tags"):
    if not cfg.has_section(sec): return []
    return [(n.strip(), v.strip()) for n, v in cfg.items(sec)]
def c14n_bytes(element):
    buf = io.BytesIO()
    element.getroottree().write_c14n(buf, with_comments=False)
    return buf.getvalue()
def c14n_bytes_node(element):
    tmp = etree.fromstring(etree.tostring(element))
    buf = io.BytesIO()
    etree.ElementTree(tmp).write_c14n(buf, with_comments=False)
    return buf.getvalue()

def build_xml_tree(cfg):
    nsmap = {"dmb": NS["dmb"], "dtf": NS["dtf"], "dtt": NS["dtt"], "dsi": NS["dsi"], "xsi": NS["xsi"]}
    root = etree.Element(qname("dmb", "DeviceMessageBatch"), nsmap=nsmap)
    etree.SubElement(root, "SchemaVersion").text = get_str(cfg, "batch", "schema_version", "3.10")
    bh = etree.SubElement(root, "BatchHeader")
    etree.SubElement(bh, "batchCreationDate").text = get_str(cfg, "batch", "batch_creation_date", iso8601_now_offset())
    seq = get_int(cfg, "batch", "batch_sequence_number", 1)
    etree.SubElement(bh, "batchSequenceNumber").text = str(seq)
    device_id = get_str(cfg, "batch", "device_id", "00000")
    etree.SubElement(bh, "deviceId").text = device_id
    etree.SubElement(bh, "deviceModule").text = get_str(cfg, "batch", "device_module", "ValidationInspection_EMV")
    body = etree.SubElement(root, "BatchBody")
    mwh  = etree.SubElement(body, "MessageWithHMAC")
    msg  = etree.SubElement(mwh, "Message")
    hdr = etree.SubElement(msg, "Header")
    etree.SubElement(hdr, "generationDate").text = get_str(cfg, "header", "generation_date", iso8601_now_z())
    etree.SubElement(hdr, "transactionStatus").text = get_str(cfg, "header", "transaction_status", "COMPLETE")
    loc = etree.SubElement(msg, "Location")
    etree.SubElement(loc, "stopPointId").text = get_str(cfg, "location", "stop_point_id", "0")
    etree.SubElement(loc, "transportMode").text = get_str(cfg, "location", "transport_mode", "METRO")
    duc = etree.SubElement(msg, "DeviceUsageContext")
    etree.SubElement(duc, "transporterBE").text = str(get_int(cfg, "device_usage_context", "transporter_be", 4))
    te = etree.SubElement(msg, "TravelEvent")
    fm = etree.SubElement(te, "FareMedia")
    etree.SubElement(fm, "mediaTypeId").text = str(get_int(cfg, "travel_event", "media_type_id", 3))
    mai = etree.SubElement(te, "MediaAdditionalInfo")
    pci = etree.SubElement(mai, "PaymentCardInfo")
    etree.SubElement(pci, "chipBasedAuthorizationStatus").text = get_str(cfg, "payment_card", "chip_based_authorization_status", "ZERO_AMOUNT_TRANSACTION")
    etree.SubElement(pci, "issuerCountryCode").text = get_str(cfg, "payment_card", "issuer_country_code", "764")
    etree.SubElement(pci, "issuerIdentificationNumber").text = get_str(cfg, "payment_card", "issuer_identification_number", "0")
    etree.SubElement(pci, "applicationIdentifier").text = get_str(cfg, "payment_card", "application_identifier", "a0000000031010")
    emv_tags = etree.SubElement(pci, "emvTags")
    for name, value in parse_emv_tags(cfg):
        t = etree.SubElement(emv_tags, "emvTag")
        etree.SubElement(t, "name").text  = name
        etree.SubElement(t, "value").text = value
    etree.SubElement(pci, "transactionCurrencyCode").text = get_str(cfg, "payment_card", "transaction_currency_code", "764")
    etree.SubElement(pci, "expiryDate").text = get_str(cfg, "payment_card", "expiry_date", "291231")
    etree.SubElement(pci, "applicationPrimaryAccountSequenceNumber").text = get_str(cfg, "payment_card", "application_primary_account_sequence_number", "1")
    etree.SubElement(pci, "paymentSchemeIdentificationMnemonic").text = get_str(cfg, "payment_card", "payment_scheme_identification_mnemonic", "Visa Credit")
    etree.SubElement(te, "authorizationMode").text = get_str(cfg, "travel_event", "authorization_mode", "LOCAL")
    etree.SubElement(te, "accessStatus").text      = get_str(cfg, "travel_event", "access_status", "GRANTED")
    etree.SubElement(te, "travelEventType").text   = get_str(cfg, "travel_event", "travel_event_type", "ENTRY")
    etree.SubElement(te, "validationModel").text   = get_str(cfg, "travel_event", "validation_model", "CHECKIN_CHECKOUT")
    dev = etree.SubElement(msg, "Device")
    etree.SubElement(dev, "deviceId").text = device_id
    etree.SubElement(dev, "deviceType").text = get_str(cfg, "device", "device_type", "11")
    etree.SubElement(dev, "deviceTransactionUID").text = get_uuid(cfg, "device", "device_transaction_uid", True)
    etree.SubElement(dev, "deviceGroupUID").text = get_uuid(cfg, "device", "device_group_uid", True)
    etree.SubElement(dev, "deviceOwnerBE").text = str(get_int(cfg, "device", "device_owner_be", 4))
    ag = etree.SubElement(msg, "Agent")
    etree.SubElement(ag, "agentId").text       = get_str(cfg, "agent", "agent_id", "")
    etree.SubElement(ag, "shiftNumber").text   = str(get_int(cfg, "agent", "shift_number", 0))
    etree.SubElement(ag, "agentProfile").text  = get_str(cfg, "agent", "agent_profile", "")
    return root

def read_pem_cert_base64(cert_path):
    with open(cert_path, "rb") as f: data = f.read().decode("utf-8")
    return re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+", "", data)

def attach_signature(cfg, root):
    mode = get_str(cfg, "signature", "mode", "placeholder").lower()
    if mode == "none":
        return root
    if mode == "placeholder":
        sig = etree.SubElement(root, "Signature")
        si  = etree.SubElement(sig, "SignedInfo")
        ref = etree.SubElement(si, "Reference", URI="")
        etree.SubElement(ref, "DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        etree.SubElement(ref, "DigestValue").text = "DIGEST"
        etree.SubElement(sig, "SignatureValue").text = "UNSIGNED"
        ki = etree.SubElement(sig, "KeyInfo")
        x  = etree.SubElement(ki, "X509Data")
        etree.SubElement(x, "X509Certificate").text = ""
        return root
    if mode == "sign":
        key_path = get_str(cfg, "signature", "private_key_path", "").strip()
        crt_path = get_str(cfg, "signature", "certificate_path", "").strip()
        if not (key_path and os.path.exists(key_path)): raise FileNotFoundError(f"Private key not found: {key_path}")
        if not (crt_path and os.path.exists(crt_path)): raise FileNotFoundError(f"Certificate not found: {crt_path}")
        # Digest over canonicalized root (Signature not yet present) with SHA-256
        from hashlib import sha256
        digest_b64 = base64.b64encode(sha256(c14n_bytes(root)).digest()).decode("ascii")
        sig = etree.SubElement(root, qname("dsi","Signature"))
        si  = etree.SubElement(sig, qname("dsi","SignedInfo"))
        etree.SubElement(si, qname("dsi","CanonicalizationMethod"),
                         Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        etree.SubElement(si, qname("dsi","SignatureMethod"),
                         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        ref = etree.SubElement(si, qname("dsi","Reference"), URI="")
        transforms = etree.SubElement(ref, qname("dsi","Transforms"))
        etree.SubElement(transforms, qname("dsi","Transform"),
                         Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        etree.SubElement(ref, qname("dsi","DigestMethod"),
                         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        etree.SubElement(ref, qname("dsi","DigestValue")).text = digest_b64
        # Sign Canonical(SignedInfo)
        with open(key_path, "rb") as f:
            pkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        signed_info_c14n = c14n_bytes_node(si)
        signature = pkey.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA256())
        etree.SubElement(sig, qname("dsi","SignatureValue")).text = base64.b64encode(signature).decode("ascii")
        ki = etree.SubElement(sig, qname("dsi","KeyInfo"))
        x  = etree.SubElement(ki, qname("dsi","X509Data"))
        etree.SubElement(x, qname("dsi","X509Certificate")).text = read_pem_cert_base64(crt_path)
        return root
    raise ValueError("signature.mode must be one of: placeholder | none | sign")

def make_filename(seq: int, when: dt.datetime | None = None):
    when = when or dt.datetime.utcnow()
    return f"{seq:09d}_{when.strftime('%Y%m%d-%H%M%S')}.sent"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()
    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    with open(args.config, "r", encoding="utf-8") as f: cfg.read_file(f)
    seq = get_int(cfg, "batch", "batch_sequence_number", 1)
    root = build_xml_tree(cfg)
    root = attach_signature(cfg, root)
    outdir = os.path.abspath(args.outdir); os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, make_filename(seq))
    xml_bytes = etree.tostring(root, encoding="utf-8", pretty_print=True)
    with open(out_path, "wb") as f: f.write(xml_bytes)
    print(out_path)

if __name__ == "__main__":
    main()
