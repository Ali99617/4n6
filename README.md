# 4n6 - Digital Forensics Analysis Tool

![Language](https://img.shields.io/badge/Language-Python%203-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-success)

##  Overview

**4n6** is a comprehensive digital forensics analysis tool designed for analyzing and examining disk structures, filesystems, and forensic artifacts. The tool provides both command-line and graphical user interface (GUI) modes for in-depth forensic investigation.

### Key Capabilities

The tool specializes in automated detection and analysis of:

- **MBR (Master Boot Record)** - Boot sector analysis with partition table parsing
- **GPT (GUID Partition Table)** - Modern partition scheme analysis with GUID extraction
- **FAT32 Filesystem** - File system metadata extraction with deleted file recovery
- **Windows Registry Hives** - Registry structure analysis and artifact extraction
- **Encryption Detection** - Advanced entropy analysis and encryption signature detection
- **Malware Indicators** - Boot sector malware detection and suspicious pattern analysis
- **Anomaly Detection** - Partition corruption, inconsistencies, and data integrity issues

##  Features

### Core Analysis Capabilities

1. **Automatic File Type Detection**
   - MBR signature verification (0x55AA)
   - GPT header detection (EFI PART)
   - FAT32 filesystem identification
   - Registry hive signature analysis (regf)

2. **Advanced MBR Analysis**
   - Boot code extraction and examination
   - Partition table parsing with validation
   - CHS (Cylinder-Head-Sector) coordinates analysis
   - LBA (Logical Block Addressing) range validation
   - Filesystem type detection from content
   - Partition overlap detection
   - CHS validity checking

3. **GPT Partition Analysis**
   - Header and backup header validation
   - GUID extraction and formatting (Mixed Endian)
   - Partition entry enumeration
   - Usable LBA range calculation
   - Deleted partition detection

4. **FAT32 Filesystem Analysis**
   - BIOS Parameter Block (BPB) parsing
   - FAT table analysis with fragmentation detection
   - Deleted file detection and recovery indicators
   - Root directory extraction
   - Orphaned cluster identification
   - Slack space analysis

5. **Windows Registry Forensics**
   - Registry hive header validation
   - Hive type detection (SYSTEM, SAM, SOFTWARE, NTUSER.DAT)
   - Major keys identification
   - UserAssist, Recent Documents, and USB device tracking
   - ShimCache/AppCompatCache analysis
   - BAM/DAM (Background Activity Moderator) detection

6. **Encryption Analysis**
   - Entropy-based encryption detection
   - BitLocker, LUKS, and FileVault signature detection
   - Randomness analysis across multiple sectors
   - Encrypted data identification

7. **Interactive Hex Viewer**
   - Professional hex dump display (offset, hex, ASCII)
   - Byte-level navigation with LBA support
   - Data Inspector with multiple data type interpretations
   - Search functionality (Hex/ASCII)
   - Configurable byte grouping
   - Selection highlighting and analysis

8. **Professional Reporting**
   - Comprehensive forensic analysis reports
   - Anomaly highlighting and severity classification
   - Practical exam question answers (الإجابات الأكاديمية)
   - Export-ready formatted output

##  Installation

### Requirements

- Python 3.6+
- tkinter (for GUI mode - usually included with Python)
- Standard library modules: struct, binascii, zlib, mmap, re, math, datetime, collections

### Setup

```bash
# Clone the repository
git clone https://github.com/Ali99617/4n6.git
cd 4n6

# No additional dependencies needed - uses only Python standard library
python3 forensic_analyzer.py
```

##  Usage

### GUI Mode (Recommended)

```bash
# Launch the graphical interface
python3 forensic_analyzer.py
```

**Features:**
- Browse and select files for analysis
- View results in organized tabs
- Interactive hex viewer with search
- One-click analysis report generation
- Copy results to clipboard

### Command Line Mode

```bash
# Analyze a specific file
python3 forensic_analyzer.py /path/to/disk_image.001

# Examples:
python3 forensic_analyzer.py MBR_image.bin
python3 forensic_analyzer.py NTUSER.DAT
python3 forensic_analyzer.py disk_partition.img
```

**Output:** Detailed forensic analysis report printed to console

##  Analysis Examples

### MBR Analysis

```
================================================================================
تحليل MBR Boot Sector
================================================================================

📦 Boot Code Area: 446 bytes
Complete Boot Code (Hex Dump):
0000: 33 C0 8E D8 8E C0 BC 00 7C B8 01 02 BB 00 7C BA ...

📋 Partition Table Entries:
--------------------------------------------------------------------------------
Partition 1:
  🚩 Bootable: Yes
  📌 Type: 0x07 (NTFS/HPFS)
  📍 Start LBA: 2048 (sector 2048)
  📏 Size: 204800 sectors (104.86 MB)
```

### Encryption Detection

```
🔐 Encryption Analysis
================================================================================

🔍 Signature-based Detection:
✅ DETECTED: BitLocker Drive Encryption

📊 Entropy Analysis (Randomness Check):
Boot Sector (0-512 bytes)     : 7.89 [████████████████████] HIGH (Encrypted/Compressed)
```

## 🔍 Supported File Formats

| Format | Extension | Support Level |
|--------|-----------|----------------|
| MBR Boot Sector | .bin, .001, .img | ✅ Full |
| GPT Partition Table | .bin, .001, .img | ✅ Full |
| FAT32 Filesystem | .fat, .img | ✅ Full |
| Windows Registry | .dat, .hive | ✅ Full |
| Raw Disk Images | .dd, .001, .img | ✅ Full |

## 📁 Project Structure

```
4n6/
├── forensic_analyzer.py          # Main application
├── knowledge_base.py             # Knowledge base for patterns
├── knowledge_base.json           # Pattern database
├── extract_pdf_knowledge.py      # Utility for data extraction
├── README.md                     # This file
└── __pycache__/                  # Python cache
```

##  Academic Use Cases

This tool is designed for:

- **Cybersecurity Students** - Learn filesystem and boot structure analysis
- **Digital Forensics Training** - Hands-on forensic investigation practice
- **Security Research** - Analyze malware effects on boot sectors
- **System Administration** - Understand disk structure and partitioning
- **Incident Response** - Investigate suspicious disk anomalies

##  Technical Details

### Memory Efficiency

- Supports large files using memory-mapped I/O (mmap) for files > 100MB
- Partial file analysis with automatic handling of incomplete disk images
- Efficient chunked reading for deep analysis

### Analysis Depth

- **MBR**: Boot code analysis, partition validation, malware pattern detection
- **FAT32**: Complete BPB parsing, cluster chain analysis, fragmentation detection
- **Registry**: Multi-level key parsing, artifact extraction, timeline construction
- **Encryption**: Multi-point entropy sampling, signature matching, probability assessment

### Data Validation

- CHS validity range checking (C < 1024, H < 255, S = 1-63)
- LBA boundary validation against file size
- Signature verification (0x55AA for MBR, "EFI PART" for GPT, "regf" for Registry)
- Structural consistency checks

##  Important Notes

1. **Read-Only Analysis** - The tool performs read-only analysis and does not modify files
2. **Large Files** - Handles files up to several GB with automatic mmap optimization
3. **Partial Images** - Automatically detects and handles partial/incomplete disk images
4. **UTF-8 Support** - Full support for Arabic and international characters
5. **Cross-Platform** - Works on Windows, Linux, and macOS

##  Output Format

Analysis reports include:

- File metadata (size, path, detection results)
- Detailed structural analysis
- Anomaly detection and severity classification
- Forensically relevant findings
- Practical exam answers (for educational contexts)
- Hex dump with formatting and interpretation

##  Educational Features

- **Practical Exam Answers** - Automatically formatted responses to common forensic questions
- **Arabic Language Support** - Full interface and output in Arabic
- **Step-by-Step Analysis** - Clear breakdown of analysis process
- **Visual Data Inspector** - Multi-format data interpretation (decimal, hex, binary, ASCII)

##  Contributing

Contributions are welcome! Please feel free to:

- Report bugs and issues
- Suggest new features
- Submit pull requests
- Share forensic patterns and signatures

##  License

MIT License - See LICENSE file for details

##  Contact & Support

- **Author**: Ali99617
- **Repository**: https://github.com/Ali99617/4n6
- **Issues**: GitHub Issues tracker

##  Acknowledgments

Thanks to the digital forensics community for patterns, signatures, and best practices.

---

**Last Updated**: December 2025  
**Version**: 1.0.0
