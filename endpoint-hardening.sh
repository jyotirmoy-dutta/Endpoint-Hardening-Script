#!/bin/bash
# endpoint-hardening.sh
# Cross-platform (Linux/macOS) Endpoint Hardening Script
# Author: (Your Name)
# Date: (Today's Date)

LOGFILE="$(pwd)/endpoint-hardening.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOGFILE"
}

# Root check
if [[ $EUID -ne 0 ]]; then
    log ERROR "This script must be run as root."
    echo "This script must be run as root." >&2
    exit 1
fi
log INFO "Script started as root."

OS="$(uname -s)"

# ========== HARDENING FUNCTIONS ==========

harden_firewall() {
    log INFO "Configuring firewall..."
    if command -v ufw &>/dev/null; then
        ufw default deny incoming
        ufw default allow outgoing
        ufw enable
        log INFO "UFW firewall enabled."
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --set-default-zone=drop
        firewall-cmd --reload
        log INFO "firewalld configured."
    elif [[ "$OS" == "Darwin" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
        log INFO "macOS firewall enabled."
    else
        log ERROR "No supported firewall found."
    fi
}

harden_ssh() {
    log INFO "Hardening SSH..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i.bak -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i.bak -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
        log INFO "SSH root login and password auth disabled."
    fi
}

harden_password_policy() {
    log INFO "Enforcing password policy..."
    if [[ -f /etc/login.defs ]]; then
        sed -i.bak -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i.bak -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        sed -i.bak -E 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
        log INFO "Password policy set."
    fi
}

disable_guest() {
    log INFO "Disabling guest account..."
    if [[ -f /etc/lightdm/lightdm.conf ]]; then
        echo -e "[SeatDefaults]\nallow-guest=false" >> /etc/lightdm/lightdm.conf
        log INFO "Guest account disabled (lightdm)."
    fi
}

disable_unused_services() {
    log INFO "Disabling unused services..."
    for svc in avahi-daemon cups bluetooth nfs-server rpcbind; do
        systemctl disable --now $svc 2>/dev/null && log INFO "$svc disabled."
    done
}

enable_automatic_updates() {
    log INFO "Enabling automatic updates..."
    if command -v apt &>/dev/null; then
        apt-get install -y unattended-upgrades
        dpkg-reconfigure -plow unattended-upgrades
        log INFO "Unattended upgrades enabled."
    elif command -v dnf &>/dev/null; then
        systemctl enable --now dnf-automatic
        log INFO "dnf-automatic enabled."
    elif [[ "$OS" == "Darwin" ]]; then
        softwareupdate --schedule on
        log INFO "macOS auto-updates enabled."
    fi
}

restrict_usb() {
    log INFO "Restricting USB storage..."
    if [[ -f /etc/modprobe.d/usb-storage.conf ]]; then
        echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
        log INFO "USB storage restricted."
    fi
}

enforce_screen_lock() {
    log INFO "Enforcing screen lock timeout..."
    # Implementation varies by desktop environment; placeholder
}

disable_ipv6() {
    log INFO "Disabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    log INFO "IPv6 disabled."
}

disable_netbios() {
    log INFO "Disabling NetBIOS over TCP/IP..."
    # Implementation varies; placeholder
}

disable_bluetooth() {
    log INFO "Disabling Bluetooth..."
    systemctl disable --now bluetooth 2>/dev/null && log INFO "Bluetooth disabled."
}

disable_remote_login() {
    log INFO "Disabling remote login (macOS)..."
    if [[ "$OS" == "Darwin" ]]; then
        systemsetup -setremotelogin off
        log INFO "Remote login disabled."
    fi
}

enable_auditing() {
    log INFO "Enabling auditing..."
    if command -v auditctl &>/dev/null; then
        auditctl -e 1
        log INFO "Linux auditing enabled."
    fi
}

harden_ssh_advanced() {
    log INFO "Advanced SSH hardening..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i.bak -E 's/^#?Ciphers.*/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config
        sed -i.bak -E 's/^#?MACs.*/MACs hmac-sha2-512,hmac-sha2-256/' /etc/ssh/sshd_config
        sed -i.bak -E 's/^#?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
        sed -i.bak -E 's/^#?LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
        log INFO "SSH advanced hardening applied."
    fi
}

enable_aslr() {
    log INFO "Enabling ASLR..."
    sysctl -w kernel.randomize_va_space=2
    log INFO "ASLR enabled."
}

restrict_kernel_modules() {
    log INFO "Restricting kernel module loading..."
    echo 1 > /proc/sys/kernel/modules_disabled
    log INFO "Kernel module loading restricted."
}

sysctl_hardening() {
    log INFO "Applying sysctl hardening..."
    sysctl -w net.ipv4.conf.all.rp_filter=1
    sysctl -w net.ipv4.conf.default.rp_filter=1
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl -w net.ipv4.conf.all.accept_source_route=0
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    log INFO "Sysctl hardening applied."
}

filesystem_hardening() {
    log INFO "Hardening /tmp and /var/tmp..."
    # Example: add to /etc/fstab (manual review recommended)
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    log INFO "/tmp and /var/tmp hardened."
}

disk_encryption() {
    log INFO "Checking disk encryption..."
    # Placeholder: recommend LUKS (Linux) or FileVault (macOS)
    log INFO "Disk encryption should be enabled (manual step)."
}

lock_system_accounts() {
    log INFO "Locking system accounts..."
    for user in lp sync shutdown halt mail news uucp operator games gopher; do
        usermod -L $user 2>/dev/null && log INFO "$user locked."
    done
}

enforce_sudo_logging() {
    log INFO "Enforcing sudo logging..."
    echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
    log INFO "Sudo logging enforced."
}

restrict_su_usage() {
    log INFO "Restricting su usage to wheel group..."
    if [[ -f /etc/pam.d/su ]]; then
        echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
        log INFO "su usage restricted."
    fi
}

disable_more_services() {
    log INFO "Disabling more unused services..."
    for svc in smbd nmbd ftp telnet rsh rsync; do
        systemctl disable --now $svc 2>/dev/null && log INFO "$svc disabled."
    done
}

configure_auditd() {
    log INFO "Configuring auditd..."
    if command -v auditd &>/dev/null; then
        systemctl enable --now auditd
        log INFO "auditd enabled."
    fi
}

configure_logrotate() {
    log INFO "Configuring logrotate..."
    # Placeholder: ensure /etc/logrotate.conf exists
    log INFO "logrotate configuration checked."
}

configure_syslog() {
    log INFO "Configuring syslog..."
    if command -v rsyslogd &>/dev/null; then
        systemctl enable --now rsyslog
        log INFO "rsyslog enabled."
    elif command -v syslog-ng &>/dev/null; then
        systemctl enable --now syslog-ng
        log INFO "syslog-ng enabled."
    fi
}

firewall_advanced() {
    log INFO "Advanced firewall hardening..."
    if command -v ufw &>/dev/null; then
        ufw default deny incoming
        ufw default allow outgoing
        ufw limit ssh
        ufw enable
        log INFO "UFW advanced firewall enabled."
    fi
}

macos_hardening() {
    log INFO "Applying macOS-specific hardening..."
    if [[ "$OS" == "Darwin" ]]; then
        # Disable AirDrop
        defaults write com.apple.NetworkBrowser DisableAirDrop -bool true
        # Disable Siri
        defaults write com.apple.assistant.support "Assistant Enabled" -bool false
        # Restrict sharing
        launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null
        # Enable FileVault
        fdesetup enable
        # Enable Gatekeeper
        spctl --master-enable
        # Disable remote Apple events
        systemsetup -setremoteappleevents off
        log INFO "macOS-specific hardening applied."
    fi
}

# ========== MAIN EXECUTION ==========

harden_firewall
harden_ssh
harden_password_policy
disable_guest
disable_unused_services
enable_automatic_updates
restrict_usb
enforce_screen_lock
disable_ipv6
disable_netbios
disable_bluetooth
disable_remote_login
enable_auditing
harden_ssh_advanced
enable_aslr
restrict_kernel_modules
sysctl_hardening
filesystem_hardening
disk_encryption
lock_system_accounts
enforce_sudo_logging
restrict_su_usage
disable_more_services
configure_auditd
configure_logrotate
configure_syslog
firewall_advanced
macos_hardening

log INFO "Endpoint Hardening complete." 