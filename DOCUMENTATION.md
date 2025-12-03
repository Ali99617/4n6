# Comprehensive Documentation: 4n6 Digital Forensics Analysis Tool

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Design](#architecture-design)
3. [Core Components](#core-components)
4. [Technical Implementation](#technical-implementation)
5. [Usage Patterns](#usage-patterns)
6. [Academic Applications](#academic-applications)

## System Overview

### Purpose and Scope

**4n6** is an advanced digital forensics analysis tool specifically engineered for educational and professional examination of disk structures and file systems. The tool implements industry-standard forensic methodologies for MBR, GPT, FAT32, and Windows Registry analysis.

### Project Goals

1. **Educational**: Provide students with practical forensic investigation capabilities
2. **Research**: Enable security researchers to analyze disk artifacts
3. **Forensic**: Support digital forensics practitioners in incident investigation
4. **Accessibility**: Offer both CLI and GUI interfaces for varied user preferences

---

## Architecture Design

### 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface Layer                     │
│  ┌─────────────┬──────────────┬────────────────────────┐   │
│  │   CLI Mode  │   GUI Mode   │  Interactive Hex View  │   │
│  └─────────────┴──────────────┴────────────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
┌─────────────────────────────────────────────────────────────┐
│                  Analysis Engine Layer                       │
│  ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌────────┐   │
│  │  File Type │ │   MBR      │ │   GPT     │ │ FAT32  │   │
│  │ Detector   │ │ Analyzer   │ │ Analyzer  │ │Analyzer│   │
│  └────────────┘ └────────────┘ └───────────┘ └────────┘   │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────┐   │
│  │  Registry  │ │ Encryption │ │  Malware Detection   │   │
│  │  Analyzer  │ │ Detector   │ │  & Anomaly Analysis  │   │
│  └────────────┘ └────────────┘ └──────────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
┌─────────────────────────────────────────────────────────────┐
│               Data Processing Layer                          │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐        │
│  │  File Reader │  │   mmap I/O  │  │   Parser   │        │
│  └──────────────┘  └─────────────┘  └────────────┘        │
└────────────────────┬────────────────────────────────────────┘
                     │
┌─────────────────────────────────────────────────────────────┐
│               Storage/Reporting Layer                        │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐        │
│  │  Report Gen  │  │  Clipboard  │  │   Console  │        │
│  └──────────────┘  └─────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### 2. Class Structure

#### **ForensicAnalyzer Class** (Core Analysis Engine)

**Responsibilities:**
- File reading and validation
- Automatic file type detection
- Sector-level data parsing
- Report generation

**Key Methods:**
```python
# File Operations
- read_file()                        # Load file into memory/mmap
- read_at_offset()                   # Efficient sector reading
- detect_partial_image()             # Identify incomplete images

# Analysis Operations  
- detect_file_type()                 # Auto-detect format
- analyze_mbr()                      # MBR parsing & validation
- analyze_gpt()                      # GPT header & entry analysis
- analyze_fat32()                    # FAT structure examination
- analyze_registry()                 # Registry hive parsing
- analyze_encryption()               # Entropy-based detection
- detect_malware_patterns()          # Boot sector analysis

# Utility Methods
- calculate_entropy()                # Statistical analysis
- format_guid()                      # GUID conversion
- get_partition_type_name()          # Type translation
```

#### **ForensicGUI Class** (User Interface)

**Responsibilities:**
- Tkinter-based GUI framework
- Multi-tabbed analysis display
- Interactive hex viewer
- Real-time data inspection

**Tabs:**
1. MBR Analysis
2. GPT Analysis
3. Filesystem Details
4. Registry Analysis
5. Encryption Detection
6. Anomaly Report
7. Interactive Hex View

---

## Core Components

### 1. File Type Detection System

**Detection Order:**
1. Check for MBR signature (0x55AA at offset 510)
2. Check for GPT header ("EFI PART" at offset 512)
3. Check for FAT32 signature
4. Check for Registry signature ("regf" at offset 0)

**Signature Verification:**
```
MBR     → Magic: 0x55AA (little-endian at offset 510)
GPT     → Magic: "EFI PART" (8 bytes at offset 512)
FAT32   → Label: Contains "FAT32" + Signature 0x55AA
Registry→ Magic: "regf" (4 bytes at offset 0)
```

### 2. MBR Analysis Module

**Boot Sector Structure (512 bytes):**
- Offset 0-445: Boot code
- Offset 446-509: Partition table (4 × 16-byte entries)
- Offset 510-511: Boot signature (0x55AA)

**Partition Entry Structure (16 bytes each):**
```
Byte 0:        Boot flag (0x80=bootable, 0x00=not)
Bytes 1-3:     CHS start address
Byte 4:        Partition type (0x07=NTFS, 0x0C=FAT32, etc.)
Bytes 5-7:     CHS end address
Bytes 8-11:    LBA start (little-endian)
Bytes 12-15:   Partition size in sectors (little-endian)
```

**Validation Checks:**
- CHS Range: Cylinder < 1024, Head < 255, Sector 1-63
- LBA Range: Start LBA ≤ Max LBA, End within file bounds
- No overlapping partitions
- Boot signature presence

### 3. GPT Analysis Module

**GPT Header Structure:**
- Offset 512: "EFI PART" signature
- Offset 520-523: Disk GUID (mixed endian)
- Offset 568-575: First usable LBA
- Offset 576-583: Last usable LBA
- Offset 588-591: Entry count (usually 128)
- Offset 592-595: Entry size (usually 128 bytes)

**Partition Entry (128 bytes):**
- Offset 0-15: Partition type GUID
- Offset 16-31: Unique partition GUID
- Offset 32-39: Starting LBA
- Offset 40-47: Ending LBA
- Offset 48-63: Attributes
- Offset 64-127: Partition name (UTF-16LE)

### 4. FAT32 Filesystem Module

**BIOS Parameter Block (BPB):**
- Offset 11-12: Bytes per sector (typically 512)
- Offset 13: Sectors per cluster
- Offset 14-15: Reserved sectors
- Offset 16: Number of FATs (typically 2)
- Offset 20-23: Sectors per FAT (32-bit)
- Offset 44-47: Root directory cluster

**Fat Analysis Features:**
- Cluster chain following
- Deleted file detection
- Fragmentation analysis
- Orphaned cluster identification

### 5. Windows Registry Module

**Registry Hive Header (4096 bytes):**
- Offset 0-3: "regf" signature
- Offset 4-7: Primary sequence number
- Offset 8-11: Secondary sequence number
- Offset 12-19: Last write timestamp
- Offset 20-23: Major version
- Offset 24-27: Minor version
- Offset 32-39: Root key offset

**Supported Hive Types:**
- SYSTEM: Hardware profiles, drivers, services
- SOFTWARE: Installed applications, settings
- SAM: User account information
- NTUSER.DAT: User preferences, run keys
- SECURITY: Security policies

### 6. Encryption Detection Engine

**Multi-Level Detection:**
1. **Signature Detection**: BitLocker, LUKS, FileVault patterns
2. **Entropy Analysis**: Randomness measurement (0-8.0 scale)
3. **Multi-point Sampling**: Boot, middle, and end sectors
4. **Threshold Evaluation**:
   - > 7.8: Highly likely encryption/compression
   - 7.5-7.8: Probable encryption
   - 7.0-7.5: Possible encryption
   - < 7.0: Unlikely encrypted

---

## Technical Implementation

### 1. Memory Management

**Large File Handling (> 100MB):**
```python
# Use memory-mapped I/O (mmap)
self.mmap_obj = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
# Read 10MB for initial analysis
self.data = self.mmap_obj[:min(10*1024*1024, file_size)]
```

**Benefits:**
- Efficient memory usage
- System-optimized paging
- Support for multi-GB files

### 2. Data Parsing Strategy

**Binary Structure Parsing:**
```python
# Example: Parse partition entry
import struct

entry_data = file_data[offset:offset+16]
boot_flag = entry_data[0]
start_lba = struct.unpack('<I', entry_data[8:12])[0]  # Little-endian
size_sectors = struct.unpack('<I', entry_data[12:16])[0]
```

**Key Format Strings:**
- `<I`: Little-endian 32-bit unsigned int
- `<H`: Little-endian 16-bit unsigned int
- `<Q`: Little-endian 64-bit unsigned int
- `>H`: Big-endian 16-bit (GPT)

### 3. Entropy Calculation

**Shannon Entropy Formula:**
```
H = -Σ(p_i * log2(p_i)) for each byte value
Range: 0 (uniform) to 8.0 (random)
```

**Implementation:**
```python
def calculate_entropy(self, data):
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy
```

### 4. Anomaly Detection Logic

**MBR Anomalies:**
1. Overlapping partitions
2. Start LBA beyond file size
3. Invalid CHS coordinates
4. Unusually high LBA values (> 2^32)
5. Partitions extending beyond disk

**Classification:**
- Hard failures: Indicates corruption
- Soft anomalies: Unusual but possible configurations

---

## Usage Patterns

### 1. GUI Mode Workflow

```
Start Application
  ↓
Select File (Browse Dialog)
  ↓
Click "Analyze"
  ↓
Auto-Detect File Type
  ↓
Run Appropriate Analysis
  ↓
Display Results in Tabs
  ↓
Interact with Hex Viewer
```

### 2. CLI Mode Workflow

```bash
python3 forensic_analyzer.py <filepath>
# Output: Complete analysis report to console
```

### 3. Hex Viewer Navigation

**Keyboard Shortcuts:**
- Ctrl+F: Search (Hex/ASCII)
- Ctrl+C: Copy selection
- Ctrl+Home: Jump to offset dialog
- Ctrl+G: Jump to LBA

**Mouse Actions:**
- Click: Select byte
- Drag: Range selection
- Scroll: Navigate sectors

---

## Academic Applications

### 1. Curriculum Integration

**Digital Forensics Courses:**
- **Week 3**: MBR analysis and partition recovery
- **Week 4**: GPT modern partition schemes
- **Week 5**: FAT32 file system internals
- **Week 7**: Registry artifacts and timeline creation
- **Week 8**: Encryption detection and evidence
- **Week 9**: Malware forensics and rootkit detection

### 2. Lab Exercises

**Exercise 1: MBR Recovery**
- Provide corrupted MBR image
- Students use tool to identify issues
- Report on partition recovery feasibility

**Exercise 2: GPT Forensics**
- Analyze multi-partition UEFI disk
- Extract partition GUIDs
- Verify backup GPT integrity

**Exercise 3: Registry Timeline**
- Extract file access times
- Construct user activity timeline
- Document suspicious applications

**Exercise 4: Encryption Detection**
- Analyze encrypted vs. unencrypted sectors
- Compare entropy values
- Identify encryption signatures

### 3. Research Applications

- **Malware Analysis**: Detect bootkit modifications
- **Disk Imaging**: Validate image integrity
- **Data Recovery**: Identify orphaned partitions
- **Security Audits**: Check for suspicious modifications

---

## Performance Characteristics

| Operation | Large File | Small File |
|-----------|-----------|-----------|
| File Detection | < 1ms | < 1ms |
| MBR Analysis | 10-50ms | 5-10ms |
| GPT Analysis | 20-100ms | 10-20ms |
| FAT32 Full Parse | 1-5s | 100-500ms |
| Registry Parse | 500ms-2s | 100-300ms |
| Entropy Analysis | 1-10s | 100-500ms |

---

## Dependencies

**Python Standard Library Only:**
- struct: Binary parsing
- binascii: Hex conversion
- zlib: Compression detection
- mmap: Memory-mapped I/O
- re: Regex patterns
- math: Mathematical functions
- datetime: Timestamp handling
- tkinter: GUI (optional)

---

## Future Enhancements

1. **Extended Filesystems**: EXT4, BTRFS support
2. **Mobile Forensics**: iOS/Android artifacts
3. **Timeline Analysis**: Automatic timeline generation
4. **ML-based Detection**: Anomaly prediction
5. **Batch Processing**: Multiple file analysis
6. **Report Export**: PDF/Excel output formats

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Target Audience**: Students, Researchers, Practitioners
**Made by**: Student Ali Abdullah Al-Ammari
