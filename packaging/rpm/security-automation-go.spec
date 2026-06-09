Name:           security-automation-go
Version:        1.5.0
Release:        1%{?dist}
Summary:        Security automation operator daemon
License:        Proprietary
BuildArch:      x86_64

%description
Cloudflare/CrowdSec/OpenResty integration with operator UI.

%pre
getent group security-automation >/dev/null || groupadd --system security-automation
getent passwd security-automation >/dev/null || \
    useradd --system --no-create-home --gid security-automation \
        --home /var/lib/security-automation-go \
        --shell /sbin/nologin security-automation
exit 0

%post
%systemd_post cf-sync.service
install -d -m 750 -o security-automation -g security-automation \
    /var/lib/security-automation-go \
    /var/lib/security-automation-go/runtime
install -d -m 755 -o root -g root /etc/security-automation-go
touch /etc/security-automation-go/security-automation.env
chmod 0644 /etc/security-automation-go/security-automation.env
install -d -m 755 -o security-automation -g security-automation \
    /var/log/security-automation-go

%preun
%systemd_preun cf-sync.service

%postun
%systemd_postun_with_restart cf-sync.service

%files
%attr(0755, root, root) /usr/local/bin/cf-sync
/lib/systemd/system/cf-sync.service
%config(noreplace) %attr(0640, root, security-automation) /etc/security-automation-go/security-automation.yaml
%dir %attr(0750, security-automation, security-automation) /var/lib/security-automation-go
%dir %attr(0750, security-automation, security-automation) /var/lib/security-automation-go/runtime
%dir %attr(0755, security-automation, security-automation) /var/log/security-automation-go
