FROM python:3.12-slim-bookworm@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /work

COPY app /work/app
# The runtime monitor and replay entry live OUTSIDE source_root on purpose.
COPY monitor /opt/vp/monitor
COPY entry.py /opt/vp/entry.py
RUN chmod 0755 /opt/vp/entry.py && chmod -R a+rX /opt/vp /work/app

CMD ["/bin/bash"]
