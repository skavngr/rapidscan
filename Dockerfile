# golismero install has been skipped. 
# See issue https://github.com/golismero/golismero/issues/59
# RUN apt-get install -y golismero
# This fails, so we skip completely for now. See issue https://github.com/kislyuk/argcomplete/issues/348
# RUN cd /opt && git clone https://github.com/golismero/golismero.git && cd golismero && pip install -r requirements.txt && ln -s /opt./golismero/golismero.py /usr/bin/golismero

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get -yu dist-upgrade -y
RUN apt-get install -y ca-certificates
RUN echo "deb https://http.kali.org/kali kali-rolling main contrib non-free" > ./etc/apt/sources.list
RUN echo "deb http://old.kali.org/kali sana main non-free contrib" >> ./etc/apt/sources.list

RUN apt-get -yq install \
      python3 \
      host \
      whois \
      sslyze \
      wapiti \
      nmap \
      dmitry \
      dnsenum \
      dnsmap \
      dnsrecon \
      dnswalk \
      dirb \
      wafw00f \
      whatweb \
      nikto \
      lbd \
      xsser \
      fierce \
      theharvester \
      davtest \
      uniscan \
      amass \
      wget && \
    apt-get -yq autoremove && \
    apt-get clean && \
    rm -rf /var/lib/{apt,dpkg,cache,log}

ADD rapidscan.py /usr/local/bin/rapidscan.py
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/rapidscan.py"]
