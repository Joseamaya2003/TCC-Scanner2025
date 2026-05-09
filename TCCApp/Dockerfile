FROM debian:bullseye-slim

WORKDIR /shared

RUN apt-get update && apt-get install -y \
    bash \
    grep\
    coreutils \
    python3 \
    && apt-get clean

COPY format_logs.sh /format_logs.sh 
COPY HTML.py /HTML.py
RUN chmod +x /format_logs.sh

CMD [ "/format_logs.sh" ]