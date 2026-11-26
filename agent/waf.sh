#!/usr/bin/env bash
# WAF opcional de Shinji SOC: nginx + ModSecurity + reglas OWASP CRS, con los
# paquetes de Debian. Se pone entre el tunel de Cloudflare y cada aplicacion:
#
#   Cloudflare -> cloudflared -> WAF (127.0.0.1:PUERTO) -> aplicacion
#
# El agente lee lo que el WAF detecta (/var/log/shinji-soc-waf/audit.log) y
# lo manda al panel. Arranca en modo "deteccion": registra sin bloquear.
#
# El instalador del agente lo deja como comando: shinji-soc-waf. Uso (root):
#   shinji-soc-waf instalar
#   shinji-soc-waf agregar NOMBRE PUERTO DESTINO    p. ej.: agregar amp 8081 http://127.0.0.1:8080
#   shinji-soc-waf quitar NOMBRE
#   shinji-soc-waf modo deteccion|bloqueo
#   shinji-soc-waf estado
#   shinji-soc-waf desinstalar
# (sin el agente instalado: sudo bash waf.sh ...)
#
# Variables opcionales para "agregar":
#   ESCUCHAR=127.0.0.1   direccion donde escucha el WAF (0.0.0.0 si cloudflared
#                        corre en un contenedor y no llega a 127.0.0.1)
#   CONFIAR="127.0.0.1 ::1"   desde donde se acepta la cabecera CF-Connecting-IP
#                        con la IP real del visitante (agrega la red del
#                        contenedor de cloudflared si corresponde)

set -euo pipefail

PROG=$(basename "$0")
[ "$PROG" = shinji-soc-waf ] || PROG="bash $0"

CONF_DIR=/etc/shinji-soc-waf
LOG_DIR=/var/log/shinji-soc-waf
NGINX_CONF_D=/etc/nginx/conf.d
CRS_SETUP=/etc/modsecurity/crs/crs-setup.conf
CRS_RULES=/usr/share/modsecurity-crs/rules

die() { echo "Error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "ejecuta con sudo o como root"; }
installed() { [ -f "$CONF_DIR/modsecurity.conf" ]; }
need_installed() { installed || die "el WAF no esta instalado: corre primero '$PROG instalar'"; }

reload_nginx() {
  nginx -t -q 2>/dev/null || { nginx -t; die "la configuracion de nginx no es valida; no se recargo"; }
  if systemctl is-active --quiet nginx; then
    systemctl reload nginx
  else
    systemctl enable --now nginx >/dev/null 2>&1 || systemctl start nginx
  fi
}

current_mode() {
  if grep -q "SecRuleEngine On" "$CONF_DIR/modo.conf" 2>/dev/null; then echo bloqueo; else echo deteccion; fi
}

write_mode() {
  case "$1" in
    deteccion) engine=DetectionOnly ;;
    bloqueo) engine=On ;;
    *) die "modo desconocido: '$1' (usa deteccion o bloqueo)" ;;
  esac
  cat > "$CONF_DIR/modo.conf" <<EOF
# Lo cambia "$PROG modo deteccion|bloqueo".
# DetectionOnly: registra lo que bloquearia, sin bloquear. On: bloquea (403).
SecRuleEngine $engine
EOF
}

cmd_instalar() {
  need_root
  command -v apt-get >/dev/null || die "este script necesita Debian, Ubuntu o Proxmox (apt)"
  had_nginx=0
  dpkg -s nginx >/dev/null 2>&1 && had_nginx=1

  echo "Instalando nginx, ModSecurity y las reglas OWASP CRS..."
  # Que nginx no arranque solo al instalarse: con el sitio por defecto
  # tomaria el puerto 80, que puede estar en uso por otra aplicacion.
  policy_created=0
  if [ ! -e /usr/sbin/policy-rc.d ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
    policy_created=1
  fi
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx libnginx-mod-http-modsecurity modsecurity-crs \
    || { [ "$policy_created" = 1 ] && rm -f /usr/sbin/policy-rc.d; die "no se pudieron instalar los paquetes"; }
  [ "$policy_created" = 1 ] && rm -f /usr/sbin/policy-rc.d

  if [ "$had_nginx" = 0 ] && [ -L /etc/nginx/sites-enabled/default ]; then
    # nginx recien instalado para el WAF: sin el sitio de ejemplo del puerto 80.
    rm -f /etc/nginx/sites-enabled/default
  fi
  [ -f "$CRS_SETUP" ] || die "no se encontro $CRS_SETUP (paquete modsecurity-crs)"

  mkdir -p "$CONF_DIR/sitios" "$LOG_DIR"
  [ -f "$CONF_DIR/modo.conf" ] || write_mode deteccion
  [ -f "$CONF_DIR/exclusiones.conf" ] || cat > "$CONF_DIR/exclusiones.conf" <<'EOF'
# Exclusiones propias, para falsos positivos. Se cargan despues de las reglas
# CRS. Ejemplos:
#   SecRuleRemoveById 942100
#   SecRuleUpdateTargetById 942100 "!ARGS:password"
# Despues de editar: shinji-soc-waf modo deteccion   (o bloqueo; recarga nginx)
EOF

  cat > "$CONF_DIR/modsecurity.conf" <<EOF
# Generado por waf.sh: se reescribe al reinstalar. Los cambios propios van en
# exclusiones.conf; el modo, con "$PROG modo".
Include $CONF_DIR/modo.conf

SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \\
  "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \\
  "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Un archivo subido mas grande se revisa solo en parte, sin rechazarlo.
SecRequestBodyLimitAction ProcessPartial
SecRequestBodyJsonDepthLimit 512
SecArgumentsLimit 1000
SecRule &ARGS "@ge 1000" \\
  "id:200007,phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"
SecRule REQBODY_ERROR "!@eq 0" \\
  "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" \\
  "id:200004,phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

# Sin revisar las respuestas: no retrasa descargas, WebSockets ni eventos en
# vivo de las aplicaciones.
SecResponseBodyAccess Off

SecTmpDir /tmp/
SecDataDir /tmp/
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile /etc/nginx/unicode.mapping 20127
SecStatusEngine Off

# Registro de lo detectado, una linea JSON por peticion. Sin cuerpos (pueden
# llevar contrasenas): cabecera, peticion y reglas que coincidieron.
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?!)"
SecAuditLogParts ABHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog $LOG_DIR/audit.log

# Reglas OWASP CRS (paquete modsecurity-crs), nivel de paranoia 1.
Include $CRS_SETUP
Include $CRS_RULES/*.conf
Include $CONF_DIR/exclusiones.conf
EOF

  cat > "$NGINX_CONF_D/shinji-soc-waf.conf" <<'EOF'
# WAF de Shinji SOC (waf.sh). Los sitios estan en /etc/shinji-soc-waf/sitios.
map $http_upgrade $shinji_waf_connection {
    default upgrade;
    ''      close;
}
map $http_x_forwarded_proto $shinji_waf_proto {
    default $http_x_forwarded_proto;
    ''      $scheme;
}
include /etc/shinji-soc-waf/sitios/*.conf;
EOF

  # El registro lo escribe nginx (www-data); el agente lo lee por el grupo adm.
  touch "$LOG_DIR/audit.log"
  chown www-data:adm "$LOG_DIR" "$LOG_DIR/audit.log"
  chmod 2750 "$LOG_DIR"
  chmod 0640 "$LOG_DIR/audit.log"

  cat > /etc/logrotate.d/shinji-soc-waf <<EOF
$LOG_DIR/audit.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

  reload_nginx
  echo
  echo "WAF instalado en modo $(current_mode)."
  echo "Siguiente paso: $PROG agregar NOMBRE PUERTO DESTINO   (ver '$PROG' sin argumentos)"
}

validate_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "nombre invalido: usa minusculas, numeros y guiones (max. 32)"; }

cmd_agregar() {
  need_root; need_installed
  [ $# -eq 3 ] || die "uso: $PROG agregar NOMBRE PUERTO DESTINO   (p. ej. agregar amp 8081 http://127.0.0.1:8080)"
  name=$1 port=$2 dest=$3
  validate_name "$name"
  [[ "$port" =~ ^[0-9]{2,5}$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || die "puerto invalido: usa uno entre 1024 y 65535"
  re_dest='^https?://[][A-Za-z0-9.:_-]+/?$'
  [[ "$dest" =~ $re_dest ]] || die "destino invalido: usa algo como http://127.0.0.1:8080"
  listen=${ESCUCHAR:-127.0.0.1}
  [[ "$listen" =~ ^[0-9a-fA-F.:]+$ ]] || die "ESCUCHAR invalido: '$listen'"
  [[ "$listen" == *:* && "$listen" != \[* ]] && listen="[$listen]"
  trusted=${CONFIAR:-127.0.0.1 ::1}
  real_ip_lines=""
  for net in $trusted; do
    [[ "$net" =~ ^[0-9a-fA-F.:/]+$ ]] || die "CONFIAR invalido: '$net'"
    real_ip_lines+="    set_real_ip_from $net;"$'\n'
  done
  if ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && [ ! -f "$CONF_DIR/sitios/$name.conf" ]; then
    die "el puerto $port ya esta en uso"
  fi

  cat > "$CONF_DIR/sitios/$name.conf" <<EOF
# Sitio "$name" del WAF de Shinji SOC: $listen:$port -> $dest
server {
    listen $listen:$port;
    server_name _;

    modsecurity on;
    modsecurity_rules_file $CONF_DIR/modsecurity.conf;

    # IP real del visitante: la manda Cloudflare y solo se acepta si la
    # peticion llega desde cloudflared (CONFIAR).
$real_ip_lines    real_ip_header CF-Connecting-IP;

    # Log de acceso con la IP real: el agente lo encuentra solo y lo usa
    # para detectar escaneos y fuerza bruta.
    access_log /var/log/nginx/shinji-waf-$name.access.log combined;
    error_log /var/log/nginx/shinji-waf-$name.error.log warn;

    client_max_body_size 0;

    location / {
        proxy_pass $dest;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$shinji_waf_connection;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$shinji_waf_proto;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_request_buffering off;
    }
}
EOF
  if ! nginx -t -q 2>/dev/null; then
    nginx -t || true
    rm -f "$CONF_DIR/sitios/$name.conf"
    die "nginx no acepto el sitio; no se agrego"
  fi
  reload_nginx
  echo "Sitio '$name' agregado: $listen:$port -> $dest (modo $(current_mode))."
  echo "En Cloudflare, en tu tunel, pestana Routes: edita la Published application de esa"
  echo "aplicacion y cambia Service URL a http://${listen/0.0.0.0/IP_DE_ESTE_SERVIDOR}:$port"
}

cmd_quitar() {
  need_root; need_installed
  [ $# -eq 1 ] || die "uso: $PROG quitar NOMBRE"
  validate_name "$1"
  [ -f "$CONF_DIR/sitios/$1.conf" ] || die "no existe el sitio '$1'"
  rm -f "$CONF_DIR/sitios/$1.conf"
  reload_nginx
  echo "Sitio '$1' quitado. En Cloudflare, vuelve a poner la Service URL de la aplicacion."
}

cmd_modo() {
  need_root; need_installed
  [ $# -eq 1 ] || die "uso: $PROG modo deteccion|bloqueo"
  write_mode "$1"
  reload_nginx
  echo "Modo del WAF: $(current_mode)."
}

cmd_estado() {
  need_installed
  echo "Modo: $(current_mode)"
  echo "nginx: $(systemctl is-active nginx 2>/dev/null || true)"
  echo "Sitios:"
  found=0
  for f in "$CONF_DIR"/sitios/*.conf; do
    [ -e "$f" ] || continue
    found=1
    echo "  $(basename "$f" .conf): $(sed -n 's/^# Sitio "[^"]*" del WAF de Shinji SOC: //p' "$f")"
  done
  [ "$found" = 1 ] || echo "  (ninguno)"
  echo "Registro: $LOG_DIR/audit.log ($(wc -l < "$LOG_DIR/audit.log" 2>/dev/null || echo 0) lineas)"
}

cmd_desinstalar() {
  need_root
  rm -f "$NGINX_CONF_D/shinji-soc-waf.conf" /etc/logrotate.d/shinji-soc-waf
  rm -rf "$CONF_DIR"
  if command -v nginx >/dev/null && nginx -t -q 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || true
  fi
  echo "WAF quitado (configuracion de Shinji SOC). Quedan los registros en $LOG_DIR y los paquetes."
  echo "En Cloudflare, vuelve a poner la Service URL de cada aplicacion (sin el WAF)."
  echo "Para borrar tambien los paquetes: apt-get remove nginx libnginx-mod-http-modsecurity modsecurity-crs"
}

case "${1:-}" in
  instalar) shift; cmd_instalar "$@" ;;
  agregar) shift; cmd_agregar "$@" ;;
  quitar) shift; cmd_quitar "$@" ;;
  modo) shift; cmd_modo "$@" ;;
  estado) shift; cmd_estado "$@" ;;
  desinstalar) shift; cmd_desinstalar "$@" ;;
  *) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
