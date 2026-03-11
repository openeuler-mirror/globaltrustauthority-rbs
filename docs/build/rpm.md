# globaltrustauthority-rbs RPM Package Guide

This guide provides comprehensive information about installing, using, and building RPM packages for the globaltrustauthority-rbs (Global Trust Authority Resource Broker Service) project.

## Table of Contents

- [Introduction](#introduction)
- [System Requirements](#system-requirements)
- [Package Overview](#package-overview)
- [Installation](#installation)
- [Usage](#usage)
- [Service Management](#service-management)
- [Building RPM Packages](#building-rpm-packages)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

## Introduction

globaltrustauthority-rbs provides resource brokering and secure resource management with attestation support. The project is distributed as RPM packages for easy installation and management on supported Linux distributions.

### What You'll Find in This Guide

- **For End Users**: Installation instructions, usage examples, and service management
- **For System Administrators**: Service configuration, troubleshooting, and maintenance
- **For Developers**: Build instructions, package customization, and development setup

## System Requirements

### Supported Operating Systems

**Currently Supported:**
- **OpenEuler** (tested and recommended)

> **Note**: Support for additional operating systems may be added in future releases. The build process and package structure are designed to be extensible to other RPM-based distributions.

### System Prerequisites

Before installation, ensure your system meets the following requirements:

- **Operating System**: OpenEuler 24.03 or later (latest stable release recommended)
- **Systemd**: Required for service management
- **Network**: Internet access for initial installation (if using package repositories)

## Package Overview

globaltrustauthority-rbs consists of three RPM packages:

### rbs Package

The **Resource Broker Service** (RBS) package provides the core RBS daemon and service management.

**Components:**
- Binary executable: `/usr/bin/rbs`
- Configuration file: `/etc/rbs/rbs.yaml`
- Systemd service unit: `/usr/lib/systemd/system/rbs.service`
- Data directories:
  - `/var/lib/rbs` - Application data and state
  - `/var/log/rbs` - Log files
- System user: `rbs` (created automatically)

**Dependencies:**
- systemd (for service management)

### rbc Package

The **Resource Broker Client** (RBC) package provides the client tool for interacting with the Resource Broker Service (RBS).

**Components:**
- Binary executable: `/usr/bin/rbc`
- Configuration file: `/etc/rbc/rbc.yaml`

**Use Cases:**
- Connect to RBS servers
- Request keys and resources
- Perform attestation operations

### rbs-cli Package

The **RBS Command Line Tools** package provides administrative and client utilities.

**Components:**
- `/usr/bin/rbs-cli` - CLI with subcommands `admin` (management) and `client` (RBS operations)

**Use Cases:**
- System administration
- Configuration management
- Client operations

## Installation

### Obtaining RPM Packages

RPM packages can be obtained from:

1. **Official Releases**: Download from the project repository
2. **Building from Source**: See [Building RPM Packages](#building-rpm-packages) section

### Installation Methods

#### Method 1: Install All Packages (Recommended)

Install all three packages at once:

```bash
sudo rpm -ivh rbs-*.rpm rbc-*.rpm rbs-cli-*.rpm
```

If you built from source, copy the RPMs from `rpm-build/RPMS/<arch>/` (e.g. `x86_64` or `aarch64`) to the target host, then run the command above.

#### Method 2: Install Individual Packages

Install packages based on your needs:

```bash
# Install RBS service only
sudo rpm -ivh rbs-*.rpm

# Install Resource Broker Client (rbc) only
sudo rpm -ivh rbc-*.rpm

# Install CLI tools only
sudo rpm -ivh rbs-cli-*.rpm
```

#### Method 3: Upgrade Existing Installation

To upgrade from a previous version:

```bash
sudo rpm -Uvh rbs-*.rpm rbc-*.rpm rbs-cli-*.rpm
```

### Post-Installation Verification

After installation, verify that everything is set up correctly:

```bash
# Check installed packages
rpm -qa | grep -E "rbs|rbc"

# Verify binaries are in PATH
which rbs rbc rbs-cli

# Check service status (if rbs package installed)
sudo systemctl status rbs.service

# Verify configuration files exist
ls -l /etc/rbs/rbs.yaml
# If rbc is installed:
ls -l /etc/rbc/rbc.yaml

# Check system user was created (for rbs package)
id rbs
```

### Initial Configuration

1. **Review Configuration**:
   ```bash
   sudo cat /etc/rbs/rbs.yaml
   ```

2. **Edit Configuration** (if needed):
   ```bash
   sudo vi /etc/rbs/rbs.yaml
   ```

3. **Restart Service** (if configuration changed):
   ```bash
   sudo systemctl restart rbs.service
   ```

## Usage

### Using the RBS Service

The RBS service runs as a systemd daemon. Once installed and started, it listens for client connections.

**Check Service Status:**
```bash
sudo systemctl status rbs.service
```

**View Service Logs:**
```bash
# View recent logs
sudo journalctl -u rbs.service -n 50

# Follow logs in real-time
sudo journalctl -u rbs.service -f
```

### Using the RBC Client

Use the `rbc` binary (Resource Broker Client; server connection options may be added in future releases):

```bash
# Basic usage
rbc --help
# Or run directly (current placeholder behavior)
rbc
```

### Using CLI Tools

**rbs-cli** - Administrative and client operations (subcommands `admin`, `client`):
```bash
rbs-cli --help
rbs-cli admin --help
rbs-cli client --help
```

## Service Management

The RBS service is managed through systemd. The service is automatically enabled and started during installation.

### Basic Service Operations

```bash
# Start the service
sudo systemctl start rbs.service

# Stop the service
sudo systemctl stop rbs.service

# Restart the service
sudo systemctl restart rbs.service

# Reload configuration (not implemented in default unit; use restart instead)
# sudo systemctl reload rbs.service

# Check service status
sudo systemctl status rbs.service

# Enable service to start on boot
sudo systemctl enable rbs.service

# Disable service from starting on boot
sudo systemctl disable rbs.service
```

### Service Logs

```bash
# View all logs
sudo journalctl -u rbs.service

# View logs since today
sudo journalctl -u rbs.service --since today

# View logs for a specific time range
sudo journalctl -u rbs.service --since "2024-01-01" --until "2024-01-02"

# View only error messages
sudo journalctl -u rbs.service -p err
```

### Service Configuration

The service configuration is located at `/etc/rbs/rbs.yaml`. After modifying the configuration:

1. Validate the configuration (if validation tools are available)
2. Reload or restart the service:
   ```bash
   sudo systemctl restart rbs.service
   ```

## Building RPM Packages

This section is for developers and system administrators who need to build RPM packages from source.

### Prerequisites for Building

#### System Requirements

**Currently Supported Build Environment:**
- **OpenEuler** (recommended for building)

> **Note**: While the build process is currently optimized for OpenEuler, the build system is designed to be extensible. Future versions may support additional build environments.

#### Required Build Tools

Install the following packages on your build system:

**On OpenEuler:**
```bash
sudo yum install -y rpm-build rpmdevtools gcc gcc-c++ make
```

**For other RPM-based distributions** (when support is added):
```bash
# RHEL/CentOS 7
sudo yum install -y rpm-build rpmdevtools gcc gcc-c++ make

# RHEL/CentOS 8+ or Fedora
sudo dnf install -y rpm-build rpmdevtools gcc gcc-c++ make
```

#### Rust Toolchain

Install the Rust toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify installation:
```bash
cargo --version
rustc --version
```

### Quick Build

The simplest way to build all RPM packages:

```bash
./scripts/build-rpm.sh
```

This script will:
1. Check for required tools (cargo, rpmbuild)
2. Build the Rust project in release mode
3. Build all three RPM packages (rbs, rbc, rbs-cli)
4. Place the RPM files in `rpm-build/RPMS/<arch>/` (where `<arch>` is `x86_64` or `aarch64`)

### Custom Version and Release

Specify custom version and release numbers:

```bash
VERSION=1.0.0 RELEASE=2 ./scripts/build-rpm.sh
```

Default values:
- `VERSION=0.1.0`
- `RELEASE=1`

### Build Output

After successful build, RPM packages will be located in:

```
rpm-build/RPMS/x86_64/          # or under aarch64 for ARM build output
├── rbs-0.1.0-1.x86_64.rpm      # ARM: rbs-0.1.0-1.aarch64.rpm
├── rbc-0.1.0-1.x86_64.rpm
└── rbs-cli-0.1.0-1.x86_64.rpm
```

### Manual Build Process

For advanced users who prefer manual control:

1. **Build Rust binaries:**
   ```bash
   cargo build --release
   ```

2. **Build individual RPM packages:**
   ```bash
   # Build RBS RPM
   rpmbuild -bb rpm/rbs.spec \
       --define "_topdir $(pwd)/rpm-build" \
       --define "_project_root $(pwd)" \
       --define "version 0.1.0" \
       --define "release 1" \
       --buildroot "$(pwd)/rpm-build/BUILDROOT"

   # Build Resource Broker Client (rbc) RPM
   rpmbuild -bb rpm/rbc.spec \
       --define "_topdir $(pwd)/rpm-build" \
       --define "_project_root $(pwd)" \
       --define "version 0.1.0" \
       --define "release 1" \
       --buildroot "$(pwd)/rpm-build/BUILDROOT"

   # Build RBS-CLI RPM
   rpmbuild -bb rpm/rbs-cli.spec \
       --define "_topdir $(pwd)/rpm-build" \
       --define "_project_root $(pwd)" \
       --define "version 0.1.0" \
       --define "release 1" \
       --buildroot "$(pwd)/rpm-build/BUILDROOT"
   ```

## Troubleshooting

### Installation Issues

#### Error: Package conflicts or dependencies not met

**Solution**: Check for conflicting packages or missing dependencies:
```bash
# Check for conflicts
rpm -qa | grep -i rbs

# Check dependencies
rpm -qpR rbs-*.rpm
```

#### Error: Permission denied

**Solution**: Ensure you're using `sudo` for installation:
```bash
sudo rpm -ivh rbs-*.rpm
```

### Service Issues

#### Service fails to start

1. **Check service status:**
   ```bash
   sudo systemctl status rbs.service
   ```

2. **Check logs for errors:**
   ```bash
   sudo journalctl -u rbs.service -n 50
   ```

3. **Verify configuration:**
   ```bash
   sudo cat /etc/rbs/rbs.yaml
   # Check for syntax errors or invalid settings
   ```

4. **Check permissions:**
   ```bash
   ls -la /var/lib/rbs /var/log/rbs
   sudo chown -R rbs:rbs /var/lib/rbs /var/log/rbs
   ```

5. **Verify system user exists:**
   ```bash
   id rbs
   # If missing, the service installation may have failed
   ```

#### Service stops unexpectedly

1. **Check system resources:**
   ```bash
   free -h
   df -h
   ```

2. **Review logs for crash information:**
   ```bash
   sudo journalctl -u rbs.service --since "1 hour ago"
   ```

3. **Check for system errors:**
   ```bash
   dmesg | tail -50
   ```

### Build Issues

#### Error: `rpmbuild: command not found`

**Solution**: Install RPM build tools:
```bash
# On OpenEuler
sudo yum install -y rpm-build rpmdevtools gcc gcc-c++ make
```

#### Error: `linker 'cc' not found`

**Solution**: Install C compiler:
```bash
# On OpenEuler
sudo yum install -y gcc gcc-c++ make
```

#### Error: `cargo: command not found`

**Solution**: Install Rust toolchain:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Error: `File not found: target/release/rbs` or `target/release/rbs-cli`

**Solution**: Ensure the Rust project is built first (builds all workspace binaries including rbs, rbc, rbs-cli):
```bash
cargo build --release
```

#### Error: `Bad exit status from %prep`

**Solution**: This usually indicates a problem with the spec file. Check that:
- All required files exist
- Paths in the spec file are correct
- The project root is properly defined

## Advanced Topics

### Package Information

Query package information:

```bash
# List all files in a package
rpm -qlp rbs-*.rpm

# Show package information
rpm -qip rbs-*.rpm

# Show package dependencies
rpm -qpR rbs-*.rpm

# Verify installed package integrity
rpm -V rbs
```

### Uninstallation

To remove installed packages:

```bash
# Remove all packages
sudo rpm -e rbs rbc rbs-cli

# Remove individual package
sudo rpm -e rbs
```

**Note**: Uninstalling the `rbs` package will stop and disable the service automatically. Back up `/etc/rbs/rbs.yaml` (and `/etc/rbc/rbc.yaml` if needed) before removal if you want to preserve custom configuration.

### Package Signing

For production deployments, consider signing RPM packages:

```bash
# Generate GPG key (if not exists)
gpg --gen-key

# Sign package
rpm --addsign rbs-*.rpm rbc-*.rpm rbs-cli-*.rpm

# Verify signature
rpm --checksig rbs-*.rpm
```

### Creating Source RPMs (SRPMs)

To create source RPMs for distribution:

```bash
rpmbuild -bs rpm/rbs.spec \
    --define "_topdir $(pwd)/rpm-build" \
    --define "_project_root $(pwd)" \
    --define "version 0.1.0" \
    --define "release 1"
```

### Building for Different Architectures

Currently supports **x86_64** and **ARM (aarch64)**. RPMs are built for the host architecture (no spec changes needed). For cross-compilation:

1. Install the cross-compilation toolchain for the target architecture.
2. Use `cargo build --target <arch> --release` (e.g. `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`).
3. Run `rpmbuild` in the corresponding architecture environment or container.

### Spec File Structure

The RPM spec files are located in the `rpm/` directory:

- `rpm/rbs.spec` - RBS service package specification
- `rpm/rbc.spec` - Resource Broker Client package specification
- `rpm/rbs-cli.spec` - CLI tools package specification

**Key Sections:**
- **%prep**: Preparation phase (currently uses source directly)
- **%build**: Builds the Rust project
- **%install**: Installs files to buildroot
- **%pre**: Pre-installation scripts (creates user)
- **%post**: Post-installation scripts (enables service)
- **%preun**: Pre-uninstallation scripts (stops service)
- **%postun**: Post-uninstallation scripts (reloads systemd)
- **%files**: Lists files to include in the package

## Additional Resources

- **Project Repository**: See the repository root (e.g. https://gitcode.net/gta-rbs/gta-rbs or current project URL) for source and issue tracker.
- **RPM Packaging Guide**: https://rpm-packaging-guide.github.io/
- **Rust Cargo Documentation**: https://doc.rust-lang.org/cargo/
- **Systemd Service Documentation**: https://www.freedesktop.org/software/systemd/man/systemd.service.html
- **OpenEuler Documentation**: https://docs.openeuler.org/

## Getting Help

For issues, questions, or contributions:

- **Issue Tracker**: Create an issue in the project repository
- **Documentation**: Check the project documentation
- **Community**: Participate in project discussions

## Version History

- **0.1.0**: Initial RPM package release
  - Support for OpenEuler
  - Basic service management
  - Client and CLI tools
- **Doc 1.0 (2026-03-09)**: Documentation review — corrected install script reference, added rbc config to package overview, clarified intro and uninstall backup note.

---

**Last Updated**: 2026-03-09  
**Document Version**: 1.0
