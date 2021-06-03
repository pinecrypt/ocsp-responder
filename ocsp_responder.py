#!/usr/bin/env python

import os
import pytz
from asn1crypto.util import timezone
from asn1crypto import ocsp, pem
from datetime import datetime, timedelta
from math import inf
from motor.motor_asyncio import AsyncIOMotorClient
from oscrypto import asymmetric
from prometheus_client import Counter, Histogram
from sanic import Sanic, response
from sanic_prometheus import monitor

ocsp_request_valid = Counter("pinecrypt_ocsp_request_valid",
    "Valid OCSP requests")
ocsp_request_list_size = Histogram("pinecrypt_ocsp_request_list_size",
    "Histogram of OCSP request list size",
    buckets=(1, 2, 3, inf))
ocsp_request_size_bytes = Histogram("pinecrypt_ocsp_request_size_bytes",
    "Histogram of OCSP request size in bytes",
    buckets=(100, 200, 500, 1000, 2000, 5000, 10000, inf))
ocsp_request_nonces = Histogram("pinecrypt_ocsp_request_nonces",
    "Histogram of nonce count per request",
    buckets=(1, 2, 3, inf))
ocsp_response_status = Counter("pinecrypt_ocsp_response_status",
    "Status responses", ["status"])

app = Sanic("events")
monitor(app).expose_endpoint()


# Load CA certificate
with open("/server-secrets/ca_cert.pem", "rb") as fh:
    authority_cert = asymmetric.load_certificate(fh.read())

# Load CA private key
with open("/authority-secrets/ca_key.pem", "rb") as fh:
    key_buf = fh.read()
    header, _, key_der_bytes = pem.unarmor(key_buf)
    private_key = asymmetric.load_private_key(key_der_bytes)


CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)
DEBUG = bool(os.getenv("DEBUG"))
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/default?replicaSet=rs0")


@app.listener("before_server_start")
async def setup_db(app, loop):
    # TODO: find cleaner way to do this, for more see
    # https://github.com/sanic-org/sanic/issues/919
    app.ctx.db = AsyncIOMotorClient(MONGO_URI).get_default_database()


@app.route("/api/ocsp/", methods=["POST"])
async def view_ocsp_responder(request):
    sign_algo = {
        "ec": "sha1_ecdsa",
        "rsa": "sha1_rsa"
    }[authority_cert.public_key.algorithm]
    sign_func = {
        "ec": asymmetric.ecdsa_sign,
        "rsa": asymmetric.rsa_pkcs1v15_sign
    }[authority_cert.public_key.algorithm]

    ocsp_request_size_bytes.observe(len(request.body))
    ocsp_req = ocsp.OCSPRequest.load(request.body)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    response_extensions = []

    nonces = 0
    for ext in ocsp_req["tbs_request"]["request_extensions"]:
        if ext["extn_id"].native == "nonce":
            nonces += 1
            response_extensions.append(
                ocsp.ResponseDataExtension({
                    "extn_id": "nonce",
                    "critical": False,
                    "extn_value": ext["extn_value"]
                })
            )

    ocsp_request_nonces.observe(nonces)
    ocsp_request_valid.inc()

    responses = []

    ocsp_request_list_size.observe(len(ocsp_req["tbs_request"]["request_list"]))
    for item in ocsp_req["tbs_request"]["request_list"]:
        serial = item["req_cert"]["serial_number"].native
        assert serial > 0, "Serial number correctness check failed"

        doc = await app.ctx.db.certidude_certificates.find_one({"serial_number": "%x" % serial})
        if doc:
            if doc["status"] == "signed":
                status = ocsp.CertStatus(name="good", value=None)
                ocsp_response_status.labels("good").inc()
            elif doc["status"] == "revoked":
                status = ocsp.CertStatus(
                    name="revoked",
                    value={
                        "revocation_time": doc["revoked"].replace(tzinfo=pytz.UTC),
                        "revocation_reason": doc["revocation_reason"],
                    })
                ocsp_response_status.labels("revoked").inc()
            else:
                # This should not happen, if it does database is mangled
                raise ValueError("Invalid/unknown certificate status '%s'" % doc["status"])
        else:
            status = ocsp.CertStatus(name="unknown", value=None)
            ocsp_response_status.labels("unknown").inc()

        responses.append({
            "cert_id": {
                "hash_algorithm": {
                    "algorithm": "sha1"
                },
                "issuer_name_hash": authority_cert.asn1.subject.sha1,
                "issuer_key_hash": authority_cert.public_key.asn1.sha1,
                "serial_number": serial,
            },
            "cert_status": status,
            "this_update": now - CLOCK_SKEW_TOLERANCE,
            "next_update": now + timedelta(minutes=15) + CLOCK_SKEW_TOLERANCE,
            "single_extensions": []
        })

    response_data = ocsp.ResponseData({
        "responder_id": ocsp.ResponderId(name="by_key", value=authority_cert.public_key.asn1.sha1),
        "produced_at": now,
        "responses": responses,
        "response_extensions": response_extensions
    })

    return response.raw(ocsp.OCSPResponse({
        "response_status": "successful",
        "response_bytes": {
            "response_type": "basic_ocsp_response",
            "response": {
                "tbs_response_data": response_data,
                "certs": [authority_cert.asn1],
                "signature_algorithm": {"algorithm": sign_algo},
                "signature": sign_func(private_key, response_data.dump(), "sha1")
            }
        }
    }).dump(), headers={"Content-Type": "application/ocsp-response"})

app.run(port=5001, debug=DEBUG)
