FROM python
LABEL name="pinecrypt/ocsp-responder" \
      version="rc" \
      maintainer="Pinecrypt Labs <info@pinecrypt.com>"
RUN pip install asn1crypto motor oscrypto pytz sanic sanic_prometheus
ADD ocsp_responder.py /ocsp_responder.py
CMD /ocsp_responder.py
EXPOSE 5001
