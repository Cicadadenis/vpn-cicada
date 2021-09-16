YOUR_IPSEC_PSK=''
YOUR_USERNAME=''
YOUR_PASSWORD=''

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo "## $1"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Сценарий должен выполняться от имени root. Попробуйте 'sudo'"
  fi
}

check_vz() {
  if [ -f /proc/user_beancounters ]; then
    exiterr "OpenVZ VPS не поддерживается."
  fi
}

check_os() {
  os_type=$(lsb_release -si 2>/dev/null)
  os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
  [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
  case $os_type in
    [Uu]buntu)
      os_type=ubuntu
      ;;
    [Dd]ebian)
      os_type=debian
      ;;
    [Rr]aspbian)
      os_type=raspbian
      ;;
    *)
      exiterr "Этот скрипт поддерживает только Ubuntu и Debian."
      ;;
  esac

  os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  if [ "$os_ver" = "8" ] || [ "$os_ver" = "jessiesid" ]; then
    exiterr "Debian 8 или Ubuntu < 16.04 не поддерживается."
  fi
  if { [ "$os_ver" = "10" ] || [ "$os_ver" = "11" ]; } && [ ! -e /dev/ppp ]; then
    exiterr "/dev/ppp отсутствует. Debian 11 или 10 пользователей, см.: https://git.io/vpndebian10"
  fi
}

check_iface() {
  def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  def_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
  if [ -n "$def_state" ] && [ "$def_state" != "down" ]; then
    if ! uname -m | grep -qi -e '^arm' -e '^aarch64'; then
      case $def_iface in
        wl*)
          exiterr "Обнаружен беспроводной интерфейс '$def_iface'. НЕ запускайте этот сценарий на ПК или Mac!"
          ;;
      esac
    fi
    NET_IFACE="$def_iface"
  else
    eth0_state=$(cat "/sys/class/net/eth0/operstate" 2>/dev/null)
    if [ -z "$eth0_state" ] || [ "$eth0_state" = "down" ]; then
      exiterr "Не удалось обнаружить сетевой интерфейс по умолчанию."
    fi
    NET_IFACE=eth0
  fi
}

check_creds() {
  [ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
  [ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
  [ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"

  if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
    bigecho "Учетные данные VPN не задаются пользователем. Генерация случайного PSK и пароля..."
    VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 20)
    VPN_USER=Cicada3301
    VPN_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 16)
  fi

  if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
    exiterr "Необходимо указать все учетные данные VPN. Отредактируйте скрипт и повторно введите их."
  fi

  if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
    exiterr "Учетные данные VPN не должны содержать символы, не являющиеся символами ASCII."
  fi

  case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
    *[\\\"\']*)
      exiterr "Учетные данные VPN не должны содержать эти специальные символы: \\ \" '"
      ;;
  esac
}

check_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; } then
    exiterr "Указанный DNS-сервер недопустим."
  fi
}

check_iptables() {
  if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
    exiterr "Не удалось проверить IPTables. Перезагрузите компьютер и повторно запустите этот сценарий."
  fi
}

start_setup() {
  bigecho "Выполняется настройка VPN... Пожалуйста, будьте терпеливы."
  # shellcheck disable=SC2154
  trap 'dlo=$dl;dl=$LINENO' DEBUG 2>/dev/null
  trap 'finish $? $((dlo+1))' EXIT
  mkdir -p /opt/src
  cd /opt/src || exit 1
}

wait_for_apt() {
  count=0
  apt_lk=/var/lib/apt/lists/lock
  pkg_lk=/var/lib/dpkg/lock
  while fuser "$apt_lk" "$pkg_lk" >/dev/null 2>&1 \
    || lsof "$apt_lk" >/dev/null 2>&1 || lsof "$pkg_lk" >/dev/null 2>&1; do
    [ "$count" = "0" ] && echo "## Ожидание доступности apt..."
    [ "$count" -ge "100" ] && exiterr "Не удалось получить блокировку apt/dpkg."
    count=$((count+1))
    printf '%s' '.'
    sleep 3
  done
}

install_setup_pkgs_1() {
  bigecho "Установка пакетов, необходимых для установки..."
  export DEBIAN_FRONTEND=noninteractive
  (
    set -x
    apt-get -yqq update
  ) || exiterr "'apt-get update' failed."
}

install_setup_pkgs_2() {
  (
    set -x
    apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null
  ) || exiterr2
}

detect_ip() {
  bigecho "Попытка автоматического обнаружения IP-адреса этого сервера..."
  public_ip=${VPN_PUBLIC_IP:-''}
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
  check_ip "$public_ip" || public_ip=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
  check_ip "$public_ip" || exiterr "Не удается обнаружить общедоступный IP-адрес этого сервера. Определите его как переменную 'VPN_PUBLIC_IP' и повторно запустите этот скрипт."
}

install_vpn_pkgs() {
  bigecho "Установка пакетов, необходимых для VPN..."
  (
    set -x
    apt-get -yqq install libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
      libcurl4-nss-dev flex bison gcc make libnss3-tools \
      libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null
  ) || exiterr2
}

install_fail2ban() {
  bigecho "Установка Fail2Ban для защиты SSH..."
  (
    set -x
    apt-get -yqq install fail2ban >/dev/null
  ) || exiterr2
}

get_ikev2_script() {
  bigecho "Загрузка скрипта IKEv2..."
  ikev2_url="https://github.com/hwdsl2/setup-ipsec-vpn/raw/master/extras/ikev2setup.sh"
  (
    set -x
    wget -t 3 -T 30 -q -O ikev2.sh "$ikev2_url"
  ) || /bin/rm -f ikev2.sh
  [ -s ikev2.sh ] && chmod +x ikev2.sh && ln -s /opt/src/ikev2.sh /usr/bin 2>/dev/null
}

check_libreswan() {
  SWAN_VER=4.5
  ipsec_ver=$(/usr/local/sbin/ipsec --version 2>/dev/null)
  swan_ver_old=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  [ "$swan_ver_old" = "$SWAN_VER" ]
}

get_libreswan() {
  if ! check_libreswan; then
    bigecho "Downloading Libreswan..."
    swan_file="libreswan-$SWAN_VER.tar.gz"
    swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
    swan_url2="https://download.libreswan.org/$swan_file"
    (
      set -x
      wget -t 3 -T 30 -q -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -q -O "$swan_file" "$swan_url2"
    ) || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    tar xzf "$swan_file" && /bin/rm -f "$swan_file"
  else
    bigecho "Libreswan $SWAN_VER уже установлен, пропуская..."
  fi
}

install_libreswan() {
  if ! check_libreswan; then
    bigecho "Compiling и установка Libreswan, пожалуйста, подождите..."
    cd "libreswan-$SWAN_VER" || exit 1
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS=-w -s
USE_DNSSEC=false
USE_DH2=true
USE_NSS_KDF=false
FINALNSSDIR=/etc/ipsec.d
EOF
    if ! grep -qs 'VERSION_CODENAME=' /etc/os-release; then
cat >> Makefile.inc.local <<'EOF'
USE_DH31=false
USE_NSS_AVA_COPY=true
USE_NSS_IPSEC_PROFILE=false
USE_GLIBC_KERN_FLIP_HEADERS=true
EOF
    fi
    if ! grep -qs IFLA_XFRM_LINK /usr/include/linux/if_link.h; then
      echo "USE_XFRM_INTERFACE_IFLA_HEADER=true" >> Makefile.inc.local
    fi
    NPROCS=$(grep -c ^processor /proc/cpuinfo)
    [ -z "$NPROCS" ] && NPROCS=1
    (
      set -x
      make "-j$((NPROCS+1))" -s base >/dev/null && make -s install-base >/dev/null
    )

    cd /opt/src || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
      exiterr "Libreswan $SWAN_VER failed to build."
    fi
  fi
}

create_vpn_config() {
  bigecho "Создание конфигурации VPN..."

  L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
  L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.42.1'}
  L2TP_POOL=${VPN_L2TP_POOL:-'192.168.42.10-192.168.42.250'}
  XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
  XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
  DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
  DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}
  DNS_SRVS="\"$DNS_SRV1 $DNS_SRV2\""
  [ -n "$VPN_DNS_SRV1" ] && [ -z "$VPN_DNS_SRV2" ] && DNS_SRVS="$DNS_SRV1"

  # Create IPsec config
  conf_bk "/etc/ipsec.conf"
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$L2TP_NET,%v4:!$XAUTH_NET
  uniqueids=no

conn shared
  left=%defaultroute
  leftid=$public_ip
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ikev2=never
  ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,aes256-sha2;modp1024,aes128-sha1;modp1024
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
  ikelifetime=24h
  salifetime=24h
  sha2-truncbug=no

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns=$DNS_SRVS
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  cisco-unity=yes
  also=shared

include /etc/ipsec.d/*.conf
EOF

  if uname -m | grep -qi '^arm'; then
    if ! modprobe -q sha512; then
      sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
    fi
  fi

  # Specify IPsec PSK
  conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

  # Create xl2tpd config
  conf_bk "/etc/xl2tpd/xl2tpd.conf"
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

  # Set xl2tpd options
  conf_bk "/etc/ppp/options.xl2tpd"
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
ms-dns $DNS_SRV1
EOF

  if [ -z "$VPN_DNS_SRV1" ] || [ -n "$VPN_DNS_SRV2" ]; then
cat >> /etc/ppp/options.xl2tpd <<EOF
ms-dns $DNS_SRV2
EOF
  fi

  # Create VPN credentials
  conf_bk "/etc/ppp/chap-secrets"
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF

  conf_bk "/etc/ipsec.d/passwd"
  VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF
}

update_sysctl() {
  bigecho "Обновление параметров sysctl..."
  if ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf; then
    conf_bk "/etc/sysctl.conf"
cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0

net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF
  fi
}

update_iptables() {
  bigecho "Updating IPTables rules..."
  IPT_FILE=/etc/iptables.rules
  IPT_FILE2=/etc/iptables/rules.v4
  ipt_flag=0
  if ! grep -qs "hwdsl2 VPN script" "$IPT_FILE"; then
    ipt_flag=1
  fi

  ipi='iptables -I INPUT'
  ipf='iptables -I FORWARD'
  ipp='iptables -t nat -I POSTROUTING'
  res='RELATED,ESTABLISHED'
  if [ "$ipt_flag" = "1" ]; then
    service fail2ban stop >/dev/null 2>&1
    iptables-save > "$IPT_FILE.old-$SYS_DT"
    $ipi 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
    $ipi 2 -m conntrack --ctstate INVALID -j DROP
    $ipi 3 -m conntrack --ctstate "$res" -j ACCEPT
    $ipi 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
    $ipi 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
    $ipi 6 -p udp --dport 1701 -j DROP
    $ipf 1 -m conntrack --ctstate INVALID -j DROP
    $ipf 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate "$res" -j ACCEPT
    $ipf 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
    $ipf 4 -i ppp+ -o ppp+ -j ACCEPT
    $ipf 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate "$res" -j ACCEPT
    $ipf 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
    $ipf 7 -s "$XAUTH_NET" -o ppp+ -j ACCEPT
    iptables -A FORWARD -j DROP
    $ipp -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE
    $ipp -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
    echo "# Modified by hwdsl2 VPN script" > "$IPT_FILE"
    iptables-save >> "$IPT_FILE"

    if [ -f "$IPT_FILE2" ]; then
      conf_bk "$IPT_FILE2"
      /bin/cp -f "$IPT_FILE" "$IPT_FILE2"
    fi
  fi
}

enable_on_boot() {
  bigecho "Включение служб при загрузке..."
  IPT_PST=/etc/init.d/iptables-persistent
  IPT_PST2=/usr/share/netfilter-persistent/plugins.d/15-ip4tables
  ipt_load=1
  if [ -f "$IPT_FILE2" ] && { [ -f "$IPT_PST" ] || [ -f "$IPT_PST2" ]; }; then
    ipt_load=0
  fi

  if [ "$ipt_load" = "1" ]; then
    mkdir -p /etc/network/if-pre-up.d
cat > /etc/network/if-pre-up.d/iptablesload <<'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
    chmod +x /etc/network/if-pre-up.d/iptablesload

    if [ -f /usr/sbin/netplan ]; then
      mkdir -p /etc/systemd/system
cat > /etc/systemd/system/load-iptables-rules.service <<'EOF'
[Unit]
Description = Load /etc/iptables.rules
DefaultDependencies=no

Before=network-pre.target
Wants=network-pre.target

Wants=systemd-modules-load.service local-fs.target
After=systemd-modules-load.service local-fs.target

[Service]
Type=oneshot
ExecStart=/etc/network/if-pre-up.d/iptablesload

[Install]
WantedBy=multi-user.target
EOF
      systemctl enable load-iptables-rules 2>/dev/null
    fi
  fi

  for svc in fail2ban ipsec xl2tpd; do
    update-rc.d "$svc" enable >/dev/null 2>&1
    systemctl enable "$svc" 2>/dev/null
  done

  if ! grep -qs "hwdsl2 VPN script" /etc/rc.local; then
    if [ -f /etc/rc.local ]; then
      conf_bk "/etc/rc.local"
      sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
    else
      echo '#!/bin/sh' > /etc/rc.local
    fi
cat >> /etc/rc.local <<'EOF'

# Added by hwdsl2 VPN script
(sleep 15
service ipsec restart
service xl2tpd restart
echo 1 > /proc/sys/net/ipv4/ip_forward)&
exit 0
EOF
  fi
}

start_services() {
  bigecho "Запуск сервисов..."
  sysctl -e -q -p

  chmod +x /etc/rc.local
  chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*

  mkdir -p /run/pluto
  service fail2ban restart 2>/dev/null
  service ipsec restart 2>/dev/null
  service xl2tpd restart 2>/dev/null
}

show_vpn_info() {
cat <<EOF

================================================

IPsec Cicada VPN Сервер готов к использованию!

Подключитесь к новой VPN с помощью этих сведений:

Server IP: $public_ip
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD


================================================

EOF
}

check_swan_ver() {
  swan_ver_url="https://dl.ls20.com/v1/$os_type/$os_ver/swanver?arch=$os_arch&ver=$SWAN_VER"
  [ "$1" != "0" ] && swan_ver_url="$swan_ver_url&e=$2"
  swan_ver_latest=$(wget -t 3 -T 15 -qO- "$swan_ver_url")
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$' \
    && [ "$1" = "0" ] && [ -n "$SWAN_VER" ] && [ "$SWAN_VER" != "$swan_ver_latest" ] \
    && printf '%s\n%s' "$SWAN_VER" "$swan_ver_latest" | sort -C -V; then
cat <<EOF
Note: A newer version of Libreswan ($swan_ver_latest) is available.
      To update, run:
      wget https://git.io/vpnupgrade -O vpnup.sh && sudo sh vpnup.sh

EOF
  fi
}

finish() {
  check_swan_ver "$1" "$2"
  exit "$1"
}

vpnsetup() {
  check_root
  check_vz
  check_os
  check_iface
  check_creds
  check_dns
  check_iptables
  start_setup
  wait_for_apt
  install_setup_pkgs_1
  install_setup_pkgs_2
  detect_ip
  install_vpn_pkgs
  install_fail2ban
  get_ikev2_script
  get_libreswan
  install_libreswan
  create_vpn_config
  update_sysctl
  update_iptables
  enable_on_boot
  start_services
  show_vpn_info
}



export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr() { echo "Error: $1" >&2; exit 1; }
bigecho() { echo "## $1"; }
bigecho2() { printf '\e[2K\r%s' "## $1"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_dns_name() {
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}



check_os() {
  os_type=centos
  os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
  rh_file="/etc/redhat-release"
  if grep -qs "Red Hat" "$rh_file"; then
    os_type=rhel
  fi
  if grep -qs "release 7" "$rh_file"; then
    os_ver=7
  elif grep -qs "release 8" "$rh_file"; then
    os_ver=8
    grep -qi stream "$rh_file" && os_ver=8s
    grep -qi rocky "$rh_file" && os_type=rocky
    grep -qi alma "$rh_file" && os_type=alma
  elif grep -qs "Amazon Linux release 2" /etc/system-release; then
    os_type=amzn
    os_ver=2
  else
    os_type=$(lsb_release -si 2>/dev/null)
    [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
    case $os_type in
      [Uu]buntu)
        os_type=ubuntu
        ;;
      [Dd]ebian)
        os_type=debian
        ;;
      [Rr]aspbian)
        os_type=raspbian
        ;;
      [Aa]lpine)
        os_type=alpine
        ;;
      *)
        echo "Error: This script only supports one of the following OS:" >&2
        echo "       Ubuntu, Debian, CentOS/RHEL, Rocky Linux, AlmaLinux," >&2
        echo "       Amazon Linux 2 or Alpine Linux" >&2
        exit 1
        ;;
    esac
    if [ "$os_type" = "alpine" ]; then
      os_ver=$(. /etc/os-release && printf '%s' "$VERSION_ID" | cut -d '.' -f 1,2)
      if [ "$os_ver" != "3.14" ]; then
        exiterr "This script only supports Alpine Linux 3.14."
      fi
    else
      os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
    fi
  fi
}

abort_and_exit() {
  echo "Прервать. Никаких изменений не было внесено." >&2
  exit 1
}

confirm_or_abort() {
  printf '%s' "$1"
  read -r response
  case $response in
    [yY][eE][sS]|[yY])
      echo
      ;;
    *)
      abort_and_exit
      ;;
  esac
}

check_libreswan() {
  ipsec_ver=$(ipsec --version 2>/dev/null)
  swan_ver=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  if ( ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf && ! grep -qs "hwdsl2" /opt/src/run.sh ) \
    || ! printf '%s' "$ipsec_ver" | grep -q "Libreswan"; then
cat 1>&2 <<'EOF'
Error: Your must first set up the IPsec VPN server before setting up IKEv2.
       See: https://github.com/hwdsl2/setup-ipsec-vpn
EOF
    exit 1
  fi
  case $swan_ver in
    3.2[35679]|3.3[12]|4.*)
      true
      ;;
    *)
cat 1>&2 <<EOF
Error: Libreswan version '$swan_ver' is not supported.
       This script requires one of these versions:
       3.23, 3.25-3.27, 3.29, 3.31-3.32 or 4.x
       To update Libreswan, run:
       wget https://git.io/vpnupgrade -O vpnup.sh && sudo sh vpnup.sh
EOF
      exit 1
      ;;
  esac
}

check_utils_exist() {
  command -v certutil >/dev/null 2>&1 || exiterr "'certutil' not found. Abort."
  command -v crlutil >/dev/null 2>&1 || exiterr "'crlutil' not found. Abort."
  command -v pk12util >/dev/null 2>&1 || exiterr "'pk12util' not found. Abort."
}

check_container() {
  in_container=0
  if grep -qs "hwdsl2" /opt/src/run.sh; then
    in_container=1
  fi
}

show_header() {
cat <<'EOF'

Cicada Script   Copyright (c) 2020-2021 Lin Song   22 Aug 2021

EOF
}

show_usage() {
  if [ -n "$1" ]; then
    echo "Error: $1" >&2;
  fi
  show_header
cat 1>&2 <<EOF
Usage: bash $0 [options]

Options:
  --auto                        run IKEv2 setup in auto mode using default options (for initial setup only)
  --addclient [client name]     add a new client using default options
  --exportclient [client name]  export configuration for an existing client
  --listclients                 list the names of existing clients
  --revokeclient                revoke a client certificate
  --removeikev2                 remove IKEv2 and delete all certificates and keys from the IPsec database
  -h, --help                    show this help message and exit

To customize IKEv2 or client options, run this script without arguments.
For documentation, see: https://git.io/ikev2
EOF
  exit 1
}

check_ikev2_exists() {
  grep -qs "conn ikev2-cp" /etc/ipsec.conf || [ -f /etc/ipsec.d/ikev2.conf ]
}

check_client_name() {
  ! { [ "${#1}" -gt "64" ] || printf '%s' "$1" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
    || case $1 in -*) true;; *) false;; esac; }
}

check_cert_exists() {
  certutil -L -d sql:/etc/ipsec.d -n "$1" >/dev/null 2>&1
}

check_cert_exists_and_exit() {
  if certutil -L -d sql:/etc/ipsec.d -n "$1" >/dev/null 2>&1; then
    echo "Error: Certificate '$1' already exists." >&2
    abort_and_exit
  fi
}

check_cert_status() {
  cert_status=$(certutil -V -u C -d sql:/etc/ipsec.d -n "$1")
}

check_arguments() {
  if [ "$use_defaults" = "1" ]; then
    if check_ikev2_exists; then
      echo "Warning: Ignoring parameter '--auto'. Use '-h' for usage information." >&2
    fi
  fi
  if [ "$((add_client + export_client + list_clients + revoke_client))" -gt 1 ]; then
    show_usage "Invalid parameters. Specify only one of '--addclient', '--exportclient', '--listclients' or '--revokeclient'."
  fi
  if [ "$add_client" = "1" ]; then
    check_ikev2_exists || exiterr "You must first set up IKEv2 before adding a client."
    if [ -z "$client_name" ] || ! check_client_name "$client_name"; then
      exiterr "Недопустимое имя клиента. Use one word only, no special characters except '-' and '_'."
    elif check_cert_exists "$client_name"; then
      exiterr "Недопустимое имя клиента. Client '$client_name' already exists."
    fi
  fi
  if [ "$export_client" = "1" ]; then
    check_ikev2_exists || exiterr "You must first set up IKEv2 before exporting a client."
    get_server_address
    if [ -z "$client_name" ] || ! check_client_name "$client_name" \
      || [ "$client_name" = "IKEv2 VPN CA" ] || [ "$client_name" = "$server_addr" ] \
      || ! check_cert_exists "$client_name"; then
      exiterr "Недопустимое имя клиента, или клиент не существует."
    fi
    if ! check_cert_status "$client_name"; then
      printf '%s' "Error: Certificate '$client_name' " >&2
      if printf '%s' "$cert_status" | grep -q "revoked"; then
        echo "has been revoked." >&2
      elif printf '%s' "$cert_status" | grep -q "expired"; then
        echo "has expired." >&2
      else
        echo "is invalid." >&2
      fi
      exit 1
    fi
  fi
  if [ "$list_clients" = "1" ]; then
    check_ikev2_exists || exiterr "You must first set up IKEv2 before listing clients."
  fi
  if [ "$revoke_client" = "1" ]; then
    check_ikev2_exists || exiterr "You must first set up IKEv2 before revoking a client certificate."
    get_server_address
    if [ -z "$client_name" ] || ! check_client_name "$client_name" \
      || [ "$client_name" = "IKEv2 VPN CA" ] || [ "$client_name" = "$server_addr" ] \
      || ! check_cert_exists "$client_name"; then
      exiterr "Недопустимое имя клиента, или клиент не существует."
    fi
    if ! check_cert_status "$client_name"; then
      printf '%s' "Error: Certificate '$client_name' " >&2
      if printf '%s' "$cert_status" | grep -q "revoked"; then
        echo "has already been revoked." >&2
      elif printf '%s' "$cert_status" | grep -q "expired"; then
        echo "has expired." >&2
      else
        echo "is invalid." >&2
      fi
      exit 1
    fi
  fi
  if [ "$remove_ikev2" = "1" ]; then
    check_ikev2_exists || exiterr "Cannot remove IKEv2 because it has not been set up on this server."
    if [ "$((add_client + export_client + list_clients + revoke_client + use_defaults))" -gt 0 ]; then
      show_usage "Invalid parameters. '--removeikev2' cannot be specified with other parameters."
    fi
  fi
}

check_server_dns_name() {
  if [ -n "$VPN_DNS_NAME" ]; then
    check_dns_name "$VPN_DNS_NAME" || exiterr "Invalid DNS name. 'VPN_DNS_NAME' must be a fully qualified domain name (FQDN)."
  fi
}

check_custom_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; } then
    exiterr "Invalid DNS server(s)."
  fi
}

check_swan_ver() {
  if [ "$in_container" = "0" ]; then
    swan_ver_url="https://dl.ls20.com/v1/$os_type/$os_ver/swanverikev2?arch=$os_arch&ver=$swan_ver&auto=$use_defaults"
  else
    swan_ver_url="https://dl.ls20.com/v1/docker/$os_type/$os_arch/swanverikev2?ver=$swan_ver&auto=$use_defaults"
  fi
  [ "$1" != "0" ] && swan_ver_url="$swan_ver_url&e=$2"
  swan_ver_latest=$(wget -t 3 -T 15 -qO- "$swan_ver_url")
}

show_update_info() {
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$' \
    && [ "$1" = "0" ] && check_ikev2_exists && [ "$swan_ver" != "$swan_ver_latest" ] \
    && printf '%s\n%s' "$swan_ver" "$swan_ver_latest" | sort -C -V; then
    echo "Note: A newer version of Libreswan ($swan_ver_latest) is available."
    if [ "$in_container" = "0" ]; then
      echo "      To update, run:"
      echo "      wget https://git.io/vpnupgrade -O vpnup.sh && sudo sh vpnup.sh"
    else
      echo "      To update this Docker image, see: https://git.io/updatedockervpn"
    fi
    echo
  fi
}

finish() {
  check_swan_ver "$1" "$2"
  show_update_info "$1"
  exit "$1"
}

show_welcome() {
cat <<'EOF'
Добро пожаловать! Используйте этот сценарий для настройки на VPN-сервере IPsec.

Мне нужно задать вам несколько вопросов перед началом установки.
Вы можете использовать параметры по умолчанию и просто нажать enter, если вы в порядке с ними.
Cicada3301
EOF
}

show_start_setup() {
  if [ -n "$VPN_DNS_NAME" ] || [ -n "$VPN_CLIENT_NAME" ] || [ -n "$VPN_DNS_SRV1" ]; then
    bigecho "Starting IKEv2 setup in auto mode."
    printf '%s' "## Using custom option(s): "
    [ -n "$VPN_DNS_NAME" ] && printf '%s' "VPN_DNS_NAME "
    [ -n "$VPN_CLIENT_NAME" ] && printf '%s' "VPN_CLIENT_NAME "
    if [ -n "$VPN_DNS_SRV1" ] && [ -n "$VPN_DNS_SRV2" ]; then
      printf '%s' "VPN_DNS_SRV1 VPN_DNS_SRV2"
    elif [ -n "$VPN_DNS_SRV1" ]; then
      printf '%s' "VPN_DNS_SRV1"
    fi
    echo
  else
    bigecho "Запуск программы установки Cicada VPN в автоматическом режиме с использованием параметров по умолчанию."
  fi
}

show_add_client() {
  bigecho "Добавление нового клиента IKEv2 '$client_name', использование параметров по умолчанию."
}

show_export_client() {
  bigecho "Экспорт существующего клиента  '$client_name'."
}

get_export_dir() {
  export_to_home_dir=0
  if grep -qs "hwdsl2" /opt/src/run.sh; then
    export_dir="/etc/ipsec.d/"
  else
    export_dir=~/
    if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
      user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
      if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
        export_dir="$user_home_dir/"
        export_to_home_dir=1
      fi
    fi
  fi
}

get_server_ip() {
  bigecho2 "Попытка автоматического обнаружения IP этого сервера..."
  public_ip=${VPN_PUBLIC_IP:-''}
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
  check_ip "$public_ip" || public_ip=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
}

get_server_address() {
  server_addr=$(grep -s "leftcert=" /etc/ipsec.d/ikev2.conf | cut -f2 -d=)
  [ -z "$server_addr" ] && server_addr=$(grep -s "leftcert=" /etc/ipsec.conf | cut -f2 -d=)
  check_ip "$server_addr" || check_dns_name "$server_addr" || exiterr "Не удалось получить адрес VPN-сервера."
}

list_existing_clients() {
  echo "Проверка существующих клиентов ..."
  certutil -L -d sql:/etc/ipsec.d | grep -v -e '^$' -e 'IKEv2 VPN CA' -e '\.' | tail -n +3 | cut -f1 -d ' '
}

enter_server_address() {
  echo "Вы хотите, чтобы VPN-клиенты подключались к этому серверу с помощью DNS-имени,"
  printf "vpn.example.com, а не его IP-адрес? [y/N] "
  read -r response
  case $response in
    [yY][eE][sS]|[yY])
      use_dns_name=1
      echo
      ;;
    *)
      use_dns_name=0
      echo
      ;;
  esac
  if [ "$use_dns_name" = "1" ]; then
    read -rp "Введите DNS-имя этого VPN-сервера: " server_addr
    until check_dns_name "$server_addr"; do
      echo "Недопустимое DNS-имя. Необходимо ввести полное доменное имя(FQDN)."
      read -rp "Введите DNS-имя этого VPN-сервера: " server_addr
    done
  else
    get_server_ip
    echo
    echo
    read -rp "Введите IPv4-адрес этого VPN-сервера: [$public_ip] " server_addr
    [ -z "$server_addr" ] && server_addr="$public_ip"
    until check_ip "$server_addr"; do
      echo "Недопустимый IP-адрес."
      read -rp "Введите IPv4-адрес этого VPN-сервера: [$public_ip] " server_addr
      [ -z "$server_addr" ] && server_addr="$public_ip"
    done
  fi
}

enter_client_name() {
  echo
  echo "Укажите имя VPN-клиента."
  echo "Используйте только одно слово, без специальных символов, кроме '-' и '_'."
  read -rp "Имя клиента: " client_name
  [ -z "$client_name" ] && abort_and_exit
  while ! check_client_name "$client_name" || check_cert_exists "$client_name"; do
    if ! check_client_name "$client_name"; then
      echo "Недопустимое имя клиента."
    else
      echo "Недопустимое имя клиента. Клиент '$client_name' уже существует."
    fi
    read -rp "Имя клиента: " client_name
    [ -z "$client_name" ] && abort_and_exit
  done
}

enter_client_name_with_defaults() {
  echo
  echo "Укажите имя VPN-клиента."
  echo "Используйте только одно слово, без специальных символов, кроме '-' и '_'."
  read -rp "Имя клиента: [cicada3301] " client_name
  [ -z "$client_name" ] && client_name=cicada3301
  while ! check_client_name "$client_name" || check_cert_exists "$client_name"; do
      if ! check_client_name "$client_name"; then
        echo "Недопустимое имя клиента."
      else
        echo "Недопустимое имя клиента. Client '$client_name' already exists."
      fi
    read -rp "Имя клиента: [cicada3301] " client_name
    [ -z "$client_name" ] && client_name=cicada3301
  done
}

enter_client_name_for() {
  echo
  list_existing_clients
  get_server_address
  echo
  read -rp "Введите имя клиента в $1: " client_name
  [ -z "$client_name" ] && abort_and_exit
  while ! check_client_name "$client_name" || [ "$client_name" = "IKEv2 VPN CA" ] \
    || [ "$client_name" = "$server_addr" ] || ! check_cert_exists "$client_name" \
    || ! check_cert_status "$client_name"; do
    if ! check_client_name "$client_name" || [ "$client_name" = "IKEv2 VPN CA" ] \
    || [ "$client_name" = "$server_addr" ] || ! check_cert_exists "$client_name"; then
      echo "Недопустимое имя клиента, или клиент не существует."
    else
      printf '%s' "Ошибка: Сертификат '$client_name' "
      if printf '%s' "$cert_status" | grep -q "revoked"; then
        if [ "$1" = "revoke" ]; then
          echo "уже отозван."
        else
          echo "был отозван."
        fi
      elif printf '%s' "$cert_status" | grep -q "expired"; then
        echo "Истек."
      else
        echo "недействителен."
      fi
    fi
    read -rp "Введите имя клиента в $1: " client_name
    [ -z "$client_name" ] && abort_and_exit
  done
}

enter_client_cert_validity() {
  echo
  echo "Укажите срок действия (в месяцах) для данного сертификата клиента."
  read -rp "Введите число от 1 до 120: [120] " client_validity
  [ -z "$client_validity" ] && client_validity=120
  while printf '%s' "$client_validity" | LC_ALL=C grep -q '[^0-9]\+' \
    || [ "$client_validity" -lt "1" ] || [ "$client_validity" -gt "120" ] \
    || [ "$client_validity" != "$((10#$client_validity))" ]; do
    echo "Недействительный срок действия."
    read -rp "Введите число от 1 до 120: [120] " client_validity
    [ -z "$client_validity" ] && client_validity=120
  done
}

enter_custom_dns() {
  echo
  echo "По умолчанию клиенты настроены на использование Google Public DNS, когда VPN активен."
  printf "Вы хотите указать пользовательские DNS-серверы? [y/N] "
  read -r response
  case $response in
    [yY][eE][sS]|[yY])
      use_custom_dns=1
      ;;
    *)
      use_custom_dns=0
      dns_server_1=8.8.8.8
      dns_server_2=8.8.4.4
      dns_servers="8.8.8.8 8.8.4.4"
      ;;
  esac
  if [ "$use_custom_dns" = "1" ]; then
    read -rp "Введите основной DNS-сервер: " dns_server_1
    until check_ip "$dns_server_1"; do
      echo "Недопустимый DNS-сервер."
      read -rp "Введите основной DNS-сервер: " dns_server_1
    done
    read -rp "Введите дополнительный DNS-сервер (введите, чтобы пропустить): " dns_server_2
    until [ -z "$dns_server_2" ] || check_ip "$dns_server_2"; do
      echo "Недопустимый DNS-сервер."
      read -rp "Введите дополнительный DNS-сервер (введите, чтобы пропустить): " dns_server_2
    done
    if [ -n "$dns_server_2" ]; then
      dns_servers="$dns_server_1 $dns_server_2"
    else
      dns_servers="$dns_server_1"
    fi
  else
    echo "Использование Google Public DNS (8.8.8.8, 8.8.4.4)."
  fi
  echo
}

check_mobike_support() {
  mobike_support=1
  if uname -m | grep -qi -e '^arm' -e '^aarch64'; then
    modprobe -q configs
    if [ -f /proc/config.gz ]; then
      if ! zcat /proc/config.gz | grep -q "CONFIG_XFRM_MIGRATE=y"; then
        mobike_support=0
      fi
    else
      mobike_support=0
    fi
  fi
  kernel_conf="/boot/config-$(uname -r)"
  if [ -f "$kernel_conf" ]; then
    if ! grep -qs "CONFIG_XFRM_MIGRATE=y" "$kernel_conf"; then
      mobike_support=0
    fi
  fi
  # Linux kernels on Ubuntu do not support MOBIKE
  if [ "$in_container" = "0" ]; then
    if [ "$os_type" = "ubuntu" ] || uname -v | grep -qi ubuntu; then
      mobike_support=0
    fi
  else
    if uname -v | grep -qi ubuntu; then
      mobike_support=0
    fi
  fi
  if uname -a | grep -qi qnap; then
    mobike_support=0
  fi
  if [ "$mobike_support" = "1" ]; then
    bigecho2 "Проверка поддержки MOBIKE... доступный"
  else
    bigecho2 "Проверка поддержки MOBIKE... недоступно"
  fi
}

select_mobike() {
  echo
  mobike_enable=0
  if [ "$mobike_support" = "1" ]; then
    echo
    echo "Расширение MOBIKE позволяет VPN-клиентам менять точки сетевого подключения,"
    echo "Например, переключаться между мобильными данными и Wi-Fi и поддерживать туннель IPsec на новом IP-адресе."
    echo
    printf "Вы хотите включить поддержку MOBIKE? [Y/n] "
    read -r response
    case $response in
      [yY][eE][sS]|[yY]|'')
        mobike_enable=1
        ;;
      *)
        mobike_enable=0
        ;;
    esac
  fi
}

select_menu_option() {
  echo "Cicada VPN уже настроен на этом сервере."
  echo
  echo "Выберите вариант:"
  echo "  1) Добавление нового клиента"
  echo "  2) Экспорт конфигурации для существующего клиента"
  echo "  3) Список существующих клиентов"
  echo "  4) Отзыв сертификата клиента"
  echo "  5) Удалить Cicada VPN"
  echo "  6) Выход"
  read -rp "Выбор: " selected_option
  until [[ "$selected_option" =~ ^[1-6]$ ]]; do
    printf '%s\n' "$selected_option: недопустимый выбор."
    read -rp "Выбор: " selected_option
  done
}

print_server_client_info() {
cat <<EOF
Адрес VPN-сервера: $server_addr
Имя VPN-клиента: $client_name

EOF
}

confirm_setup_options() {
cat <<EOF

Мы готовы настроить уже сейчас. Ниже приведены выбранные параметры настройки.
Please double check before continuing!

======================================

EOF
  print_server_client_info
  if [ "$client_validity" = "1" ]; then
    echo "Сертификат клиента действителен в течение: 1 месяца"
  else
    echo "Сертификат клиента действителен для: $client_validity месяцев"
  fi
  if [ "$mobike_support" = "1" ]; then
    if [ "$mobike_enable" = "1" ]; then
      echo "Поддержка MOBIKE: Enable"
    else
      echo "Поддержка MOBIKE: Disable"
    fi
  else
    echo "Поддержка MOBIKE: Not available"
  fi
cat <<EOF
DNS server(s): $dns_servers

======================================

EOF
  confirm_or_abort "Вы хотите продолжить? [y/N] "
}

create_client_cert() {
  bigecho2 "Создание сертификата клиента..."
  sleep 1
  certutil -z <(head -c 1024 /dev/urandom) \
    -S -c "IKEv2 VPN CA" -n "$client_name" \
    -s "O=IKEv2 VPN,CN=$client_name" \
    -k rsa -g 3072 -v "$client_validity" \
    -d sql:/etc/ipsec.d -t ",," \
    --keyUsage digitalSignature,keyEncipherment \
    --extKeyUsage serverAuth,clientAuth -8 "$client_name" >/dev/null 2>&1 || exiterr "Failed to create client certificate."
}

create_p12_password() {
  config_file="/etc/ipsec.d/.vpnconfig"
  if grep -qs '^IKEV2_CONFIG_PASSWORD=.\+' "$config_file"; then
    . "$config_file"
    p12_password=cicada
  else
    p12_password=cicada
    [ -z "$p12_password" ] && exiterr "Could not generate a random password for .p12 file."
    mkdir -p /etc/ipsec.d
    printf '%s\n' "IKEV2_CONFIG_PASSWORD='$p12_password'" >> "$config_file"
    chmod 600 "$config_file"
  fi
}

export_p12_file() {
  bigecho2 "Создание конфигурации клиента..."
  create_p12_password
  p12_file="$export_dir$client_name.p12"
  pk12util -W "$p12_password" -d sql:/etc/ipsec.d -n "$client_name" -o "$p12_file" >/dev/null || exit 1
  if [ "$os_type" = "alpine" ]; then
    pem_file="$export_dir$client_name.temp.pem"
    openssl pkcs12 -in "$p12_file" -out "$pem_file" -passin "pass:$p12_password" -passout "pass:$p12_password" || exit 1
    openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in "$pem_file" -out "$p12_file" \
      -name "$client_name" -passin "pass:$p12_password" -passout "pass:$p12_password" || exit 1
    /bin/rm -f "$pem_file"
  fi
  if [ "$export_to_home_dir" = "1" ]; then
    chown "$SUDO_USER:$SUDO_USER" "$p12_file"
  fi
  chmod 600 "$p12_file"
}

install_base64_uuidgen() {
  if ! command -v base64 >/dev/null 2>&1 || ! command -v uuidgen >/dev/null 2>&1; then
    bigecho2 "Установка необходимых пакетов..."
    if [ "$os_type" = "ubuntu" ] || [ "$os_type" = "debian" ] || [ "$os_type" = "raspbian" ]; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get -yqq update || exiterr "'apt-get update' failed."
    fi
  fi
  if ! command -v base64 >/dev/null 2>&1; then
    if [ "$os_type" = "ubuntu" ] || [ "$os_type" = "debian" ] || [ "$os_type" = "raspbian" ]; then
      apt-get -yqq install coreutils >/dev/null || exiterr "'apt-get install' failed."
    else
      yum -y -q install coreutils >/dev/null || exiterr "'yum install' failed."
    fi
  fi
  if ! command -v uuidgen >/dev/null 2>&1; then
    if [ "$os_type" = "ubuntu" ] || [ "$os_type" = "debian" ] || [ "$os_type" = "raspbian" ]; then
      apt-get -yqq install uuid-runtime >/dev/null || exiterr "'apt-get install' failed."
    else
      yum -y -q install util-linux >/dev/null || exiterr "'yum install' failed."
    fi
  fi
}

install_uuidgen() {
  if ! command -v uuidgen >/dev/null 2>&1; then
    bigecho2 "Установка необходимых пакетов..."
    apk add -U -q uuidgen || exiterr "'apk add' failed."
  fi
}

create_mobileconfig() {
  [ -z "$server_addr" ] && get_server_address
  p12_base64=$(base64 -w 52 "$export_dir$client_name.p12")
  [ -z "$p12_base64" ] && exiterr "Не удалось закодировать.p12 файл."
  ca_base64=$(certutil -L -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" -a | grep -v CERTIFICATE)
  [ -z "$ca_base64" ] && exiterr "Не удалось закодировать сертификат ЦС VPN."
  uuid1=$(uuidgen)
  [ -z "$uuid1" ] && exiterr "Не удалось создать значение UUID."
  mc_file="$export_dir$client_name.mobileconfig"
cat > "$mc_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-128-GCM</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableRedirect</key>
        <true/>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <integer>0</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>$client_name</string>
        <key>PayloadCertificateUUID</key>
        <string>$uuid1</string>
        <key>OnDemandEnabled</key>
        <integer>0</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
          <key>Action</key>
          <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>$server_addr</string>
        <key>RemoteIdentifier</key>
        <string>$server_addr</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadOrganization</key>
      <string>Cicada VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>$server_addr</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>$client_name</string>
      <key>PayloadContent</key>
      <data>
$p12_base64
      </data>
      <key>PayloadDescription</key>
      <string>Adds a PKCS#12-formatted certificate</string>
      <key>PayloadDisplayName</key>
      <string>$client_name</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.pkcs12.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key>
      <string>$uuid1</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
    <dict>
      <key>PayloadContent</key>
      <data>
$ca_base64
      </data>
      <key>PayloadCertificateFileName</key>
      <string>ikev2vpnca</string>
      <key>PayloadDescription</key>
      <string>Adds a CA root certificate</string>
      <key>PayloadDisplayName</key>
      <string>Certificate Authority (CA)</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.root.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Cicada VPN</string>
  <key>PayloadIdentifier</key>
  <string>com.apple.vpn.managed.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF
  if [ "$export_to_home_dir" = "1" ]; then
    chown "$SUDO_USER:$SUDO_USER" "$mc_file"
  fi
  chmod 600 "$mc_file"
}

create_android_profile() {
  [ -z "$server_addr" ] && get_server_address
  p12_base64_oneline=$(base64 -w 52 "$export_dir$client_name.p12" | sed 's/$/\\n/' | tr -d '\n')
  [ -z "$p12_base64_oneline" ] && exiterr "Could not encode .p12 file."
  uuid2=$(uuidgen)
  [ -z "$uuid2" ] && exiterr "Could not generate UUID value."
  sswan_file="$export_dir$client_name.sswan"
cat > "$sswan_file" <<EOF
{
  "uuid": "$uuid2",
  "name": "IKEv2 VPN ($server_addr)",
  "type": "ikev2-cert",
  "remote": {
    "addr": "$server_addr"
  },
  "local": {
    "p12": "$p12_base64_oneline",
    "rsa-pss": "true"
  },
  "ike-proposal": "aes256-sha256-modp2048",
  "esp-proposal": "aes128gcm16"
}
EOF
  if [ "$export_to_home_dir" = "1" ]; then
    chown "$SUDO_USER:$SUDO_USER" "$sswan_file"
  fi
  chmod 600 "$sswan_file"
}

export_client_config() {
  if [ "$os_type" != "alpine" ]; then
    install_base64_uuidgen
  else
    install_uuidgen
  fi
  export_p12_file
  create_mobileconfig
  create_android_profile
}

create_ca_server_certs() {
  bigecho2 "Создание сертификатов ЦС и сервера..."
  certutil -z <(head -c 1024 /dev/urandom) \
    -S -x -n "IKEv2 VPN CA" \
    -s "O=IKEv2 VPN,CN=IKEv2 VPN CA" \
    -k rsa -g 3072 -v 120 \
    -d sql:/etc/ipsec.d -t "CT,," -2 >/dev/null 2>&1 <<ANSWERS || exiterr "Failed to create CA certificate."
y

N
ANSWERS
  sleep 1
  if [ "$use_dns_name" = "1" ]; then
    certutil -z <(head -c 1024 /dev/urandom) \
      -S -c "IKEv2 VPN CA" -n "$server_addr" \
      -s "O=IKEv2 VPN,CN=$server_addr" \
      -k rsa -g 3072 -v 120 \
      -d sql:/etc/ipsec.d -t ",," \
      --keyUsage digitalSignature,keyEncipherment \
      --extKeyUsage serverAuth \
      --extSAN "dns:$server_addr" >/dev/null 2>&1 || exiterr "Failed to create server certificate."
  else
    certutil -z <(head -c 1024 /dev/urandom) \
      -S -c "IKEv2 VPN CA" -n "$server_addr" \
      -s "O=IKEv2 VPN,CN=$server_addr" \
      -k rsa -g 3072 -v 120 \
      -d sql:/etc/ipsec.d -t ",," \
      --keyUsage digitalSignature,keyEncipherment \
      --extKeyUsage serverAuth \
      --extSAN "ip:$server_addr,dns:$server_addr" >/dev/null 2>&1 || exiterr "Failed to create server certificate."
  fi
}

add_ikev2_connection() {
  bigecho2 "Добавление нового подключения.."
  if ! grep -qs '^include /etc/ipsec\.d/\*\.conf$' /etc/ipsec.conf; then
    echo >> /etc/ipsec.conf
    echo 'include /etc/ipsec.d/*.conf' >> /etc/ipsec.conf
  fi
cat > /etc/ipsec.d/ikev2.conf <<EOF

conn ikev2-cp
  left=%defaultroute
  leftcert=$server_addr
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  leftrsasigkey=%cert
  right=%any
  rightid=%fromcert
  rightaddresspool=192.168.43.10-192.168.43.250
  rightca=%same
  rightrsasigkey=%cert
  narrowing=yes
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  auto=add
  ikev2=insist
  rekey=no
  pfs=no
  ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes128-sha2,aes256-sha2
  ikelifetime=24h
  salifetime=24h
  encapsulation=yes
EOF
  if [ "$use_dns_name" = "1" ]; then
cat >> /etc/ipsec.d/ikev2.conf <<EOF
  leftid=@$server_addr
EOF
  else
cat >> /etc/ipsec.d/ikev2.conf <<EOF
  leftid=$server_addr
EOF
  fi
  if [ -n "$dns_server_2" ]; then
cat >> /etc/ipsec.d/ikev2.conf <<EOF
  modecfgdns="$dns_servers"
EOF
  else
cat >> /etc/ipsec.d/ikev2.conf <<EOF
  modecfgdns=$dns_server_1
EOF
  fi
  if [ "$mobike_enable" = "1" ]; then
    echo "  mobike=yes" >> /etc/ipsec.d/ikev2.conf
  else
    echo "  mobike=no" >> /etc/ipsec.d/ikev2.conf
  fi
}

start_setup() {
  # shellcheck disable=SC2154
  trap 'dlo=$dl;dl=$LINENO' DEBUG 2>/dev/null
  trap 'finish $? $((dlo+1))' EXIT
}

apply_ubuntu1804_nss_fix() {
  if [ "$os_type" = "ubuntu" ] && [ "$os_ver" = "bustersid" ] && [ "$os_arch" = "x86_64" ]; then
    nss_url1="https://mirrors.kernel.org/ubuntu/pool/main/n/nss"
    nss_url2="https://mirrors.kernel.org/ubuntu/pool/universe/n/nss"
    nss_deb1="libnss3_3.49.1-1ubuntu1.5_amd64.deb"
    nss_deb2="libnss3-dev_3.49.1-1ubuntu1.5_amd64.deb"
    nss_deb3="libnss3-tools_3.49.1-1ubuntu1.5_amd64.deb"
    if tmpdir=$(mktemp --tmpdir -d vpn.XXXXX 2>/dev/null); then
      bigecho2 "Applying fix for NSS bug on Ubuntu 18.04..."
      export DEBIAN_FRONTEND=noninteractive
      if wget -t 3 -T 30 -q -O "$tmpdir/1.deb" "$nss_url1/$nss_deb1" \
        && wget -t 3 -T 30 -q -O "$tmpdir/2.deb" "$nss_url1/$nss_deb2" \
        && wget -t 3 -T 30 -q -O "$tmpdir/3.deb" "$nss_url2/$nss_deb3"; then
        apt-get -yqq update
        apt-get -yqq install "$tmpdir/1.deb" "$tmpdir/2.deb" "$tmpdir/3.deb" >/dev/null
      fi
      /bin/rm -f "$tmpdir/1.deb" "$tmpdir/2.deb" "$tmpdir/3.deb"
      /bin/rmdir "$tmpdir"
    fi
  fi
}

restart_ipsec_service() {
  if [ "$in_container" = "0" ] || { [ "$in_container" = "1" ] && service ipsec status >/dev/null 2>&1; } then
    bigecho2 "Перезапуск службы IPsec..."
    mkdir -p /run/pluto
    service ipsec restart 2>/dev/null
  fi
}

create_crl() {
  if ! crlutil -L -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" >/dev/null 2>&1; then
    crlutil -G -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" -c /dev/null >/dev/null
  fi
  sleep 2
}

add_client_cert_to_crl() {
  sn_txt=$(certutil -L -d sql:/etc/ipsec.d -n "$client_name" | grep -A 1 'Serial Number' | tail -n 1)
  sn_hex=$(printf '%s' "$sn_txt" | sed -e 's/^ *//' -e 's/://g')
  sn_dec=$((16#$sn_hex))
  [ -z "$sn_dec" ] && exiterr "Не удалось найти серийный номер сертификата клиента."
crlutil -M -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" >/dev/null <<EOF || exiterr "Failed to add client certificate to CRL."
addcert $sn_dec $(date -u +%Y%m%d%H%M%SZ)
EOF
}

reload_crls() {
  ipsec crls
}

print_client_added() {
cat <<EOF


================================================

Новый VPN-клиент "$client_name" 	Добавил!

EOF
  print_server_client_info
}

print_client_exported() {
cat <<EOF


================================================

Новый VPN-клиент "$client_name" экспортируемый!

EOF
  print_server_client_info
}

print_client_revoked() {
  echo "Сертификат '$client_name' Отозван!"
}

print_setup_complete() {
  if [ -n "$VPN_DNS_NAME" ] || [ -n "$VPN_CLIENT_NAME" ] || [ -n "$VPN_DNS_SRV1" ]; then
    printf '\e[2K\r'
  else
    printf '\e[2K\e[1A\e[2K\r'
    [ "$use_defaults" = "1" ] && printf '\e[1A\e[2K\e[1A\e[2K\e[1A\e[2K\r'
  fi
cat <<EOF
================================================

Установка Cicada VPN выполнена успешно. Сведения о режиме IKEv2:

EOF
  print_server_client_info
}

print_client_info() {
  if [ "$in_container" = "0" ]; then
cat <<'EOF'
Конфигурация клиента доступна по адресу:
EOF
  else
cat <<'EOF'
Конфигурация клиента доступна внутри Контейнер Docker на:
EOF
  fi
cat <<EOF
$export_dir$client_name.p12 (for Windows & Linux)
$export_dir$client_name.sswan (for Android)
$export_dir$client_name.mobileconfig (for iOS & macOS)

*ВАЖНО* Пароль для конфигурационных файлов клиента:
$p12_password
Запишите это, вам понадобится это для импорта!
EOF
cat <<'EOF'


================================================

EOF
}

check_ipsec_conf() {
  if grep -qs "conn ikev2-cp" /etc/ipsec.conf; then
    echo "Error:  configuration section found in /etc/ipsec.conf." >&2
    echo "       This script cannot automatically remove  from this server." >&2
    echo "       To manually remove , " >&2
    abort_and_exit
  fi
}

confirm_revoke_cert() {
  echo "WARNING: You have selected to revoke  client certificate '$client_name'."
  echo "         After revocation, this certificate *cannot* be used by VPN client(s)"
  echo "         to connect to this VPN server."
  echo
  confirm_or_abort "Вы уверены, что хотите отозвать '$client_name'? [y/N] "
}

confirm_remove_ikev2() {
  echo "ПРЕДУПРЕЖДЕНИЕ: Этот параметр удалит с этого VPN-сервера, но сохранит IPsec/L2TP"
  echo "         и режимы IPsec/XAuth (\"Cisco IPsec\"), если они установлены. Вся конфигурация"
  echo "         включая сертификаты и ключи, будут безвозвратно удалены."
  echo "         Это *не может* быть отменено! "
  echo
  confirm_or_abort "Вы уверены, что хотите отозвать ? [y/N] "
}

delete_ikev2_conf() {
  bigecho "Удаление /etc/ipsec.d/cicada.conf...."
  /bin/rm -f /etc/ipsec.d/ikev2.conf
}

delete_certificates() {
  echo
  bigecho "Удаление сертификатов и ключей из базы данных IPsec..."
  certutil -L -d sql:/etc/ipsec.d | grep -v -e '^$' -e 'IKEv2 VPN CA' | tail -n +3 | cut -f1 -d ' ' | while read -r line; do
    certutil -F -d sql:/etc/ipsec.d -n "$line"
    certutil -D -d sql:/etc/ipsec.d -n "$line" 2>/dev/null
  done
  crlutil -D -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" 2>/dev/null
  certutil -F -d sql:/etc/ipsec.d -n "IKEv2 VPN CA"
  certutil -D -d sql:/etc/ipsec.d -n "IKEv2 VPN CA" 2>/dev/null
  config_file="/etc/ipsec.d/.vpnconfig"
  if grep -qs '^IKEV2_CONFIG_PASSWORD=.\+' "$config_file"; then
    sed -i '/IKEV2_CONFIG_PASSWORD=/d' "$config_file"
  fi
}

print_ikev2_removed() {
  echo
  echo "Cicada VPN удален!"
}

ikev2setup() {
  check_root
  check_container
  check_os
  check_libreswan
  check_utils_exist

  use_defaults=0
  add_client=0
  export_client=0
  list_clients=0
  revoke_client=0
  remove_ikev2=0
  while [ "$#" -gt 0 ]; do
    case $1 in
      --auto)
        use_defaults=1
        shift
        ;;
      --addclient)
        add_client=1
        client_name="$2"
        shift
        shift
        ;;
      --exportclient)
        export_client=1
        client_name="$2"
        shift
        shift
        ;;
      --listclients)
        list_clients=1
        shift
        ;;
      --revokeclient)
        revoke_client=1
        client_name="$2"
        shift
        shift
        ;;
      --removeikev2)
        remove_ikev2=1
        shift
        ;;
      -h|--help)
        show_usage
        ;;
      *)
        show_usage "Unknown parameter: $1"
        ;;
    esac
  done

  check_arguments
  get_export_dir

  if [ "$add_client" = "1" ]; then
    show_header
    show_add_client
    client_validity=120
    create_client_cert
    export_client_config
    print_client_added
    print_client_info
    exit 0
  fi

  if [ "$export_client" = "1" ]; then
    show_header
    show_export_client
    export_client_config
    print_client_exported
    print_client_info
    exit 0
  fi

  if [ "$list_clients" = "1" ]; then
    show_header
    list_existing_clients
    exit 0
  fi

  if [ "$revoke_client" = "1" ]; then
    show_header
    confirm_revoke_cert
    create_crl
    add_client_cert_to_crl
    reload_crls
    print_client_revoked
    exit 0
  fi

  if [ "$remove_ikev2" = "1" ]; then
    check_ipsec_conf
    show_header
    confirm_remove_ikev2
    delete_ikev2_conf
    if [ "$os_type" = "alpine" ]; then
      ipsec auto --delete ikev2-cp
    else
      restart_ipsec_service
    fi
    delete_certificates
    print_ikev2_removed
    exit 0
  fi

  if check_ikev2_exists; then
    show_header
    select_menu_option
    case $selected_option in
      1)
        enter_client_name
        enter_client_cert_validity
        echo
        create_client_cert
        export_client_config
        print_client_added
        print_client_info
        exit 0
        ;;
      2)
        enter_client_name_for export
        echo
        export_client_config
        print_client_exported
        print_client_info
        exit 0
        ;;
      3)
        echo
        list_existing_clients
        exit 0
        ;;
      4)
        enter_client_name_for revoke
        echo
        confirm_revoke_cert
        create_crl
        add_client_cert_to_crl
        reload_crls
        print_client_revoked
        exit 0
        ;;
      5)
        check_ipsec_conf
        echo
        confirm_remove_ikev2
        delete_ikev2_conf
        if [ "$os_type" = "alpine" ]; then
          ipsec auto --delete ikev2-cp
        else
          restart_ipsec_service
        fi
        delete_certificates
        print_ikev2_removed
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
  fi

  check_cert_exists_and_exit "IKEv2 VPN CA"

  if [ "$use_defaults" = "0" ]; then
    show_header
    show_welcome
    enter_server_address
    check_cert_exists_and_exit "$server_addr"
    enter_client_name_with_defaults
    enter_client_cert_validity
    enter_custom_dns
    check_mobike_support
    select_mobike
    confirm_setup_options
  else
    check_server_dns_name
    check_custom_dns
    if [ -n "$VPN_CLIENT_NAME" ]; then
      client_name="$VPN_CLIENT_NAME"
      check_client_name "$client_name" \
        || exiterr "Недопустимое имя клиента. Используйте только одно слово, без специальных символов, кроме '-' и '_'."
    else
      client_name=cicada3301
    fi
    check_cert_exists "$client_name" && exiterr "Client '$client_name' already exists."
    client_validity=120
    show_header
    show_start_setup
    if [ -n "$VPN_DNS_NAME" ]; then
      use_dns_name=1
      server_addr="$VPN_DNS_NAME"
    else
      use_dns_name=0
      get_server_ip
      check_ip "$public_ip" || exiterr "Не удается определить общедоступный IP-адрес этого сервера."
      server_addr="$public_ip"
    fi
    check_cert_exists_and_exit "$server_addr"
    if [ -n "$VPN_DNS_SRV1" ] && [ -n "$VPN_DNS_SRV2" ]; then
      dns_server_1="$VPN_DNS_SRV1"
      dns_server_2="$VPN_DNS_SRV2"
      dns_servers="$VPN_DNS_SRV1 $VPN_DNS_SRV2"
    elif [ -n "$VPN_DNS_SRV1" ]; then
      dns_server_1="$VPN_DNS_SRV1"
      dns_server_2=""
      dns_servers="$VPN_DNS_SRV1"
    else
      dns_server_1=8.8.8.8
      dns_server_2=8.8.4.4
      dns_servers="8.8.8.8 8.8.4.4"
    fi
    check_mobike_support
    mobike_enable="$mobike_support"
  fi

  start_setup
  apply_ubuntu1804_nss_fix
  create_ca_server_certs
  create_client_cert
  export_client_config
  add_ikev2_connection
  if [ "$os_type" = "alpine" ]; then
    ipsec auto --add ikev2-cp >/dev/null
  else
    restart_ipsec_service
  fi
  print_setup_complete
  print_client_info
}

## Defer setup until we have the complete script
ikev2setup "$@"

exit 0
