%define name rbs
%define version 0.1.0
%define release 1

Summary: Resource Broker Service (RBS)
Name: %{name}
Version: %{version}
Release: %{release}
License: MulanPSL-2.0
Group: System Environment/Daemons
ExclusiveArch: x86_64 aarch64
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Resource Broker Service (RBS) is a secure resource management service that provides
resource brokering capabilities with attestation support.

%prep
# Use source code from current directory directly, no need to extract source archive

%build
# Build the entire workspace to ensure all dependencies are built
# Use project root path (rpmbuild executes in BUILD directory, need to return to project root)
cd %{_project_root}
cargo build --release

%install
rm -rf %{buildroot}

# Use project root path
cd %{_project_root}

# Install binary files
install -D -m 755 target/release/rbs %{buildroot}%{_bindir}/rbs

# Install configuration files
install -D -m 644 rbs/conf/rbs.yaml %{buildroot}%{_sysconfdir}/rbs/rbs.yaml
# SQLite bootstrap SQL (must match storage.sql_file_path after sed below)
install -D -m 644 rbs/conf/sqlite_rbs.sql %{buildroot}%{_datadir}/rbs/sqlite_rbs.sql
# Packaged defaults: use /var/lib/rbs for DB and /usr/share for schema (rbs user cannot write /root).
# Match flexibly on leading/trailing whitespace; fail the build if rewrites miss (plain sed -i is silent).
RBS_CFG=%{buildroot}%{_sysconfdir}/rbs/rbs.yaml
sed -ri \
    -e 's|^([[:space:]]*)url:[[:space:]]*"sqlite:///root/rbs.db"[[:space:]]*$|\1url: "sqlite:///var/lib/rbs/rbs.db"|' \
    -e 's|^([[:space:]]*)sql_file_path:[[:space:]]*"rbs/conf/sqlite_rbs.sql"[[:space:]]*$|\1sql_file_path: "/usr/share/rbs/sqlite_rbs.sql"|' \
    "$RBS_CFG"
grep -Eq '^[[:space:]]*url:[[:space:]]*"sqlite:///var/lib/rbs/rbs.db"' "$RBS_CFG" || exit 1
grep -Eq '^[[:space:]]*sql_file_path:[[:space:]]*"/usr/share/rbs/sqlite_rbs.sql"' "$RBS_CFG" || exit 1
grep -q 'sqlite:///root/rbs.db' "$RBS_CFG" && exit 1
grep -E '^[[:space:]]*sql_file_path:' "$RBS_CFG" | grep -q 'rbs/conf/' && exit 1

# Install systemd service file
install -D -m 644 service/rbs.service %{buildroot}/usr/lib/systemd/system/rbs.service

# Create data directories
install -d -m 755 %{buildroot}%{_localstatedir}/lib/rbs
install -d -m 755 %{buildroot}%{_localstatedir}/log/rbs

%pre
# Create rbs user if it doesn't exist
getent group rbs >/dev/null || groupadd -r rbs
getent passwd rbs >/dev/null || useradd -r -g rbs -d /var/lib/rbs -s /sbin/nologin -c "RBS daemon" rbs

%post
# Set directory permissions
chown -R rbs:rbs %{_localstatedir}/lib/rbs
chown -R rbs:rbs %{_localstatedir}/log/rbs

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable rbs.service

# Start service if system is running
if [ $1 -eq 1 ]; then
    systemctl start rbs.service || true
fi

%preun
# Stop service only on uninstall, not on upgrade
if [ $1 -eq 0 ]; then
    systemctl stop rbs.service || true
    systemctl disable rbs.service || true
fi

%postun
# Reload systemd
systemctl daemon-reload

# Restart service if this is an upgrade
if [ $1 -ge 1 ]; then
    systemctl try-restart rbs.service || true
fi

%files
%defattr(-,root,root,-)
%{_bindir}/rbs
%config(noreplace) %{_sysconfdir}/rbs/rbs.yaml
%{_datadir}/rbs/sqlite_rbs.sql
/usr/lib/systemd/system/rbs.service
%dir %{_localstatedir}/lib/rbs
%dir %{_localstatedir}/log/rbs

%changelog
* Mon Feb 24 2026 globaltrustauthority-rbs Team - 0.1.0-1
- Initial release of RBS (binary, systemd, dirs; ship sqlite_rbs.sql under /usr/share/rbs and patch packaged storage paths in /etc/rbs/rbs.yaml)
