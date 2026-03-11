%define name rbs-cli
%define version 0.1.0
%define release 1

Summary: RBS Command Line Tools
Name: %{name}
Version: %{version}
Release: %{release}
License: MulanPSL-2.0
Group: Applications/System
ExclusiveArch: x86_64 aarch64
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
RBS Command Line Tools (rbs-cli) providing admin and client subcommands
for managing and interacting with the Resource Broker Service.

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

# Install binary (rbs-cli with admin/client subcommands)
install -D -m 755 target/release/rbs-cli %{buildroot}%{_bindir}/rbs-cli

%files
%defattr(-,root,root,-)
%{_bindir}/rbs-cli

%changelog
* Mon Feb 24 2026 globaltrustauthority-rbs Team <team@gta-rbs.org> - 0.1.0-1
- Initial release of RBS CLI tools
