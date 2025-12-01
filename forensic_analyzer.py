#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة تحليل الأدلة الرقمية الشاملة
Comprehensive Digital Forensics Analysis Tool

هذه الأداة بتفحص الملفات وتكتشف نوعها تلقائياً:
- MBR boot sector
- GPT header/partition entries
- FAT32 filesystem
- Windows Registry hives

كل نوع له تحليل مفصل مع تقرير كامل
"""

import struct
import binascii
import zlib
import os
import sys
import re
import mmap
import math
from datetime import datetime, timedelta
from collections import defaultdict

# Force UTF-8 encoding for stdout/stderr to handle emojis on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass  # Python < 3.7 doesn't support reconfigure

# واجهة رسومية - tkinter جزء من المكتبة القياسية
try:
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox, ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class ForensicAnalyzer:
    """الكلاس الرئيسي للتحليل - كل الوظائف هنا"""
    
    def __init__(self, filepath):
        """نبدأ بقراءة الملف وتحضير البيانات"""
        self.filepath = filepath
        self.file_size = os.path.getsize(filepath)
        self.data = None
        self.mmap_file = None
        self.mmap_obj = None
        self.detected_type = None
        self.is_partial_image = False
        self.mbr_offsets = []
        self.multiple_mbrs = False
        
    def read_file(self, use_mmap=True):
        """قراءة الملف - استخدام mmap للملفات الكبيرة"""
        try:
            # تحديد إذا كان ملف كبير (أكبر من 100MB)
            if self.file_size > 100 * 1024 * 1024 and use_mmap:
                # استخدام mmap للملفات الكبيرة
                self.mmap_file = open(self.filepath, 'rb')
                self.mmap_obj = mmap.mmap(self.mmap_file.fileno(), 0, access=mmap.ACCESS_READ)
                # قراءة أول 10MB للتحليل الأولي
                self.data = self.mmap_obj[:min(10 * 1024 * 1024, self.file_size)]
                return True
            else:
                # قراءة الملف كله للملفات الصغيرة
                with open(self.filepath, 'rb') as f:
                    self.data = f.read()
                return True
        except Exception as e:
            print(f"❌ خطأ في قراءة الملف: {e}")
            return False
    
    def read_at_offset(self, offset, size):
        """قراءة بيانات من offset محدد - يدعم mmap"""
        if self.mmap_obj:
            if offset + size > len(self.mmap_obj):
                size = len(self.mmap_obj) - offset
            if offset < 0 or size <= 0:
                return b''
            return self.mmap_obj[offset:offset+size]
        else:
            if offset + size > len(self.data):
                size = len(self.data) - offset
            if offset < 0 or size <= 0:
                return b''
            return self.data[offset:offset+size]
    
    def close(self):
        """إغلاق الملفات المفتوحة"""
        if self.mmap_obj:
            self.mmap_obj.close()
        if self.mmap_file:
            self.mmap_file.close()
    
    def detect_partial_image(self):
        """الكشف عن الصور الجزئية"""
        # قاعدة بسيطة: إذا كان الملف أصغر من 1GB، قد يكون صورة جزئية
        # أو إذا كانت البارتشنات تتجاوز حجم الملف
        if self.file_size < 1024 * 1024 * 1024:  # أقل من 1GB
            self.is_partial_image = True
            return True
        return False
    
    def scan_mbr_offsets(self, max_scan_size=1024*1024):
        """فحص إزاحات MBR - البحث عن توقيع 0x55AA كل 512 بايت"""
        mbr_offsets = []
        scan_size = min(max_scan_size, self.file_size)
        
        # فحص كل 512 بايت
        for offset in range(0, scan_size, 512):
            sector = self.read_at_offset(offset, 512)
            if len(sector) >= 512:
                # التحقق من توقيع MBR (0x55AA في offset 510)
                signature = struct.unpack('<H', sector[510:512])[0]
                if signature == 0xAA55:
                    # التأكد أنه ليس GPT
                    if b'EFI PART' not in sector[:512]:
                        mbr_offsets.append(offset)
        
        self.mbr_offsets = mbr_offsets
        if len(mbr_offsets) > 1:
            self.multiple_mbrs = True
        return mbr_offsets
    
    def detect_file_type(self):
        """ديه الوظيفة اللي بتكتشف نوع الملف تلقائياً - بتفحص الإشارات المميزة لكل نوع"""
        
        if not self.data or len(self.data) < 512:
            return None
        
        # فحص إزاحات MBR أولاً
        mbr_offsets = self.scan_mbr_offsets()
        
        # فحص GPT أولاً - GPT Header يبدأ في LBA 1 (offset 512)
        # GPT بيكون فيه Protective MBR في LBA 0 و GPT Header في LBA 1
        if len(self.data) >= 520:  # نحتاج على الأقل 520 بايت للتحقق من توقيع GPT
            # البحث عن "EFI PART" في LBA 1 (offset 512)
            gpt_signature = self.data[512:520] if len(self.data) >= 520 else b''
            if gpt_signature[:8] == b'EFI PART':
                self.detected_type = 'GPT'
                return 'GPT'
        
        # فحص MBR - الإشارة المميزة: 0x55AA في النهاية
        if len(self.data) >= 512:
            mbr_signature = struct.unpack('<H', self.data[510:512])[0]
            if mbr_signature == 0xAA55:
                # إذا وصلنا هنا، يعني ما لقينا GPT signature، فهو MBR
                self.detected_type = 'MBR'
                return 'MBR'
        
        # فحص FAT32 - الإشارة المميزة: "FAT32" في البايتات 82-86
        if len(self.data) >= 90:
            fat32_label = self.data[82:90].strip()
            if b'FAT32' in fat32_label or b'FAT' in fat32_label:
                # نتأكد من BPB signature
                if self.data[510:512] == b'\x55\xAA':
                    self.detected_type = 'FAT32'
                    return 'FAT32'
        
        # فحص Registry - الإشارة المميزة: "regf" في أول 4 بايتات
        if len(self.data) >= 4:
            regf_signature = self.data[0:4]
            if regf_signature == b'regf':
                self.detected_type = 'REGISTRY'
                return 'REGISTRY'
        
        return None
    
    def calculate_entropy(self, data):
        """حساب entropy للكشف عن التشفير"""
        if not data or len(data) == 0:
            return 0.0
        
        # حساب تكرار البايتات
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # حساب entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_encryption_signatures(self, data):
        """الكشف عن توقيعات التشفير المعروفة"""
        signatures = []
        
        if len(data) < 512:
            return signatures
            
        # BitLocker (-FVE-FS-)
        if b'-FVE-FS-' in data[:512]:
            signatures.append("BitLocker Drive Encryption")
            
        # LUKS (LUKS\xba\xbe)
        if b'LUKS\xba\xbe' in data[:512]:
            signatures.append("LUKS (Linux Unified Key Setup)")
            
        # VeraCrypt (Random high entropy in first 512 bytes + specific offsets)
        # VeraCrypt is hard to detect by signature, usually high entropy in first sector
        # We rely on entropy for VeraCrypt, but check for lack of other signatures
        
        # FileVault 2 (CoreStorage)
        if b'CS' in data[:512] and b'Encrypted' in data[:4096]: # Simplified check
            signatures.append("FileVault 2 (Possible)")
            
        return signatures

    def detect_encryption(self, data):
        """الكشف عن التشفير باستخدام entropy analysis و signatures"""
        if len(data) < 512:
            return None, 0.0
        
        # 1. Check for signatures first
        signatures = self.detect_encryption_signatures(data)
        if signatures:
            return f"Detected Encryption Signature: {', '.join(signatures)}", self.calculate_entropy(data[:512])
        
        # 2. Entropy Analysis
        # Check multiple regions if possible
        entropy_start = self.calculate_entropy(data[:512])
        
        # If we have more data, check middle and end
        entropy_middle = 0.0
        entropy_end = 0.0
        
        if len(data) > 1024*1024:
            mid_offset = len(data) // 2
            entropy_middle = self.calculate_entropy(self.read_at_offset(mid_offset, 4096))
            entropy_end = self.calculate_entropy(self.read_at_offset(len(data)-4096, 4096))
            
            avg_entropy = (entropy_start + entropy_middle + entropy_end) / 3
            check_entropy = avg_entropy
        else:
            check_entropy = entropy_start
            
        # entropy عالي (قريب من 8) يشير إلى بيانات مشفرة أو عشوائية
        if check_entropy > 7.8:
             return "High entropy (>7.8) → Strong indication of encryption or compression", check_entropy
        elif check_entropy > 7.5:
            return "High entropy (>7.5) → Possible full-volume encryption", check_entropy
        elif check_entropy > 7.0:
            return "Moderate-high entropy → Possible encryption or compressed data", check_entropy
        
        return None, check_entropy

    def analyze_encryption(self):
        """تحليل التشفير الشامل"""
        report = []
        report.append("=" * 80)
        report.append("🔐 Encryption Analysis")
        report.append("=" * 80)
        report.append("")
        
        # 1. Signature Scan
        report.append("🔍 Signature-based Detection:")
        report.append("-" * 80)
        
        # Read first 64KB for signature scan
        header_data = self.read_at_offset(0, 65536)
        signatures = self.detect_encryption_signatures(header_data)
        
        if signatures:
            for sig in signatures:
                report.append(f"✅ DETECTED: {sig}")
                report.append("   Action: This volume appears to be encrypted. Mount with appropriate tools.")
        else:
            report.append("✅ No standard encryption headers (BitLocker/LUKS) found in boot sector.")
        report.append("")
        
        # 2. Entropy Analysis
        report.append("📊 Entropy Analysis (Randomness Check):")
        report.append("-" * 80)
        report.append("Entropy values close to 8.0 indicate encrypted or compressed data.")
        report.append("")
        
        # Sample points
        samples = [
            ("Boot Sector (0-512 bytes)", 0, 512),
            ("Filesystem Header (Offset 1MB)", 1024*1024, 4096),
            ("Middle of File", self.file_size // 2, 4096),
            ("End of File", max(0, self.file_size - 4096), 4096)
        ]
        
        high_entropy_count = 0
        total_samples = 0
        
        for name, offset, size in samples:
            if offset + size <= self.file_size:
                data_chunk = self.read_at_offset(offset, size)
                entropy = self.calculate_entropy(data_chunk)
                total_samples += 1
                
                # Visual bar
                bar_len = int((entropy / 8.0) * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                
                status = "Normal"
                if entropy > 7.5:
                    status = "HIGH (Encrypted/Compressed)"
                    high_entropy_count += 1
                elif entropy > 7.0:
                    status = "Elevated"
                
                report.append(f"   {name:<30} : {entropy:.4f} [{bar}] {status}")
        
        report.append("")
        
        # Conclusion
        report.append("📝 Conclusion:")
        if signatures:
            report.append("🔴 CONFIRMED: Volume contains encryption signatures.")
        elif high_entropy_count == total_samples and total_samples > 0:
            report.append("🟠 SUSPICIOUS: Consistently high entropy detected across the file.")
            report.append("   This strongly suggests Full Disk Encryption (TrueCrypt/VeraCrypt) or a raw compressed archive.")
        elif high_entropy_count > 0:
            report.append("🟡 WARNING: Localized high entropy detected. Specific partitions or files may be encrypted.")
        else:
            report.append("🟢 CLEAR: No evidence of full-volume encryption detected.")
            
        report.append("")
        report.append("=" * 80)
        return "\n".join(report)
    
    def detect_malware_patterns(self, boot_code):
        """الكشف عن أنماط البرمجيات الخبيثة في boot sector"""
        malware_indicators = []
        
        if not boot_code or len(boot_code) < 16:
            return malware_indicators
        
        # 1. فحص encrypted boot sectors (entropy عالي)
        entropy = self.calculate_entropy(boot_code)
        if entropy > 7.5:
            malware_indicators.append({
                'type': 'Encrypted boot sector',
                'severity': 'High',
                'description': 'Boot code shows high entropy (possible encryption/obfuscation)'
            })
        
        # 2. فحص XOR loops (نمط شائع في ransomware)
        # البحث عن أنماط XOR متكررة
        xor_patterns = [b'\x80\x30', b'\x30\x80', b'\x31\xC0', b'\xC0\x31']
        for pattern in xor_patterns:
            if boot_code.count(pattern) > 5:
                malware_indicators.append({
                    'type': 'Ransomware-style encryption pattern',
                    'severity': 'High',
                    'description': f'Multiple XOR operations detected (pattern: {binascii.hexlify(pattern).decode()})'
                })
                break
        
        # 3. فحص overwritten jump instructions
        # Jump instructions عادة تكون في أول 3 بايتات
        if len(boot_code) >= 3:
            first_bytes = boot_code[:3]
            # التحقق من أن أول بايت ليس jump instruction عادي (0xEB, 0xE9, 0xEA)
            if first_bytes[0] not in [0xEB, 0xE9, 0xEA, 0x90]:  # 0x90 = NOP
                if first_bytes[0] != 0x00 or first_bytes[1] != 0x00:
                    malware_indicators.append({
                        'type': 'Suspicious VBR modification',
                        'severity': 'Medium',
                        'description': 'Boot code does not start with standard jump instruction'
                    })
        
        # 4. فحص bootkit patterns
        # البحث عن أنماط معروفة للـ bootkits
        bootkit_patterns = [
            b'MBR', b'VBR', b'BOOT', b'LOAD'
        ]
        suspicious_strings = 0
        for pattern in bootkit_patterns:
            if pattern in boot_code:
                suspicious_strings += 1
        
        if suspicious_strings >= 3:
            malware_indicators.append({
                'type': 'Bootkit-like pattern',
                'severity': 'Medium',
                'description': 'Multiple boot-related strings found in boot code'
            })
        
        # 5. فحص partition table tampering
        # (سيتم فحصه في analyze_mbr)
        
        return malware_indicators
    
    def analyze_mbr(self):
        """تحليل MBR - هنا بنستخرج كل المعلومات المهمة من boot sector"""
        report = []
        report.append("=" * 80)
        report.append("تحليل MBR Boot Sector")
        report.append("=" * 80)
        report.append("")
        
        # الكشف عن الصور الجزئية
        self.detect_partial_image()
        if self.is_partial_image:
            report.append("⚠️  This file appears to be a partial disk image (not a full raw disk).")
            report.append("⚠️  Partition corruption, out-of-range LBAs, and oversized volume sizes")
            report.append("    are expected in partial images.")
            report.append("")
        
        # فحص إزاحات MBR
        mbr_offsets = self.scan_mbr_offsets()
        if len(mbr_offsets) > 1:
            report.append("⚠️  Multiple possible MBR signatures detected — possible tampering or partial image.")
            report.append(f"    Found MBR signatures at offsets: {', '.join([hex(o) for o in mbr_offsets])}")
            report.append("")
        elif len(mbr_offsets) == 1 and mbr_offsets[0] != 0:
            report.append(f"ℹ️  MBR signature found at offset {hex(mbr_offsets[0])} (not at offset 0)")
            report.append("")
        
        if len(self.data) < 512:
            report.append("❌ الملف صغير جداً - MBR لازم يكون 512 بايت على الأقل")
            return "\n".join(report)
        
        # استخراج boot code (أول 446 بايت)
        boot_code = self.data[0:446]
        report.append(f"📦 Boot Code Area: {len(boot_code)} bytes")
        report.append("")
        report.append("   Complete Boot Code (Hex Dump):")
        report.append("   " + "-" * 76)
        
        # عرض Boot Code كاملاً بتنسيق hex dump احترافي
        bytes_per_line = 16
        for i in range(0, len(boot_code), bytes_per_line):
            chunk = boot_code[i:i+bytes_per_line]
            
            # Offset
            offset_str = f"   {i:04X}:"
            
            # Hex values
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            hex_str = hex_str.ljust(bytes_per_line * 3 - 1)  # Pad to align ASCII
            
            # ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            report.append(f"{offset_str}  {hex_str}  |{ascii_str}|")
        
        report.append("   " + "-" * 76)
        report.append("")
        
        # استخراج partition table (4 entries × 16 bytes = 64 bytes)
        partition_table_start = 446
        report.append("📋 Partition Table Entries:")
        report.append("-" * 80)
        
        # Constants for validation
        LBA_SUSPICIOUS_THRESHOLD = 2**32 - 1  # Maximum 32-bit value
        max_lba = self.file_size // 512
        
        partitions = []
        # Comment 5: Plausibility check - scan for at least one valid entry
        has_plausible_entry = False
        
        for i in range(4):
            offset = partition_table_start + (i * 16)
            entry = self.data[offset:offset+16]
            
            if len(entry) < 16:
                continue
            
            # Parse partition entry structure
            # Byte 0: Boot flag (0x80 = bootable, 0x00 = not bootable)
            boot_flag = entry[0]
            # Bytes 1-3: Starting CHS address
            start_chs = struct.unpack('<BBB', entry[1:4])
            # Byte 4: Partition type
            partition_type = entry[4]
            # Bytes 5-7: Ending CHS address
            end_chs = struct.unpack('<BBB', entry[5:8])
            # Bytes 8-11: Starting LBA (sector)
            start_lba = struct.unpack('<I', entry[8:12])[0]
            # Bytes 12-15: Size in sectors
            size_sectors = struct.unpack('<I', entry[12:16])[0]
            
            # Comment 2: CHS range validation
            # CHS format: (head, sector_low_6_bits + cylinder_high_2_bits, cylinder_low_8_bits)
            # For simplicity, we check raw values: cylinder < 1024, head < 255, sector 1-63
            # Note: CHS encoding is complex, but we check basic ranges
            start_cylinder = (start_chs[1] & 0xC0) << 2 | start_chs[2]
            start_head = start_chs[0]
            start_sector = start_chs[1] & 0x3F
            
            end_cylinder = (end_chs[1] & 0xC0) << 2 | end_chs[2]
            end_head = end_chs[0]
            end_sector = end_chs[1] & 0x3F
            
            invalid_chs = False
            if start_cylinder >= 1024 or start_head >= 255 or start_sector < 1 or start_sector > 63:
                invalid_chs = True
            if end_cylinder >= 1024 or end_head >= 255 or end_sector < 1 or end_sector > 63:
                invalid_chs = True
            
            # Check if partition is used (non-zero type)
            if partition_type != 0:
                # Comment 5: Check for plausibility (non-zero type, non-zero LBA and size, within file range)
                if (start_lba > 0 and size_sectors > 0 and 
                    start_lba < max_lba and start_lba + size_sectors <= max_lba):
                    has_plausible_entry = True
                
                # التحقق من نوع نظام الملفات الفعلي من المحتوى (مع درجات الثقة)
                fs_heuristics = self.detect_filesystem_heuristics(start_lba, size_sectors)
                detected_fs = None
                if fs_heuristics and fs_heuristics[0]['confidence'] >= 70:
                    detected_fs = fs_heuristics[0]['type']
                
                partition_info = {
                    'index': i + 1,
                    'bootable': boot_flag == 0x80,
                    'type': partition_type,
                    'type_name': self.get_partition_type_name(partition_type),
                    'start_lba': start_lba,
                    'size_sectors': size_sectors,
                    'size_bytes': size_sectors * 512,
                    'start_chs': start_chs,
                    'end_chs': end_chs,
                    'invalid_chs': invalid_chs,
                    'detected_filesystem': detected_fs,  # نوع نظام الملفات المكتشف فعلياً
                    'filesystem_heuristics': fs_heuristics,  # جميع نتائج الكشف مع الثقة
                    'suspect': False,  # Will be set during anomaly detection
                    'raw': entry
                }
                partitions.append(partition_info)
        
        # Comment 5: Early warning if no plausible entries found
        if not has_plausible_entry and len(partitions) > 0:
            report.append("⚠️  WARNING: Although an MBR signature was found, the partition table does not contain")
            report.append("   any structurally valid entries (non-zero type with valid LBA ranges).")
            report.append("   The partition table is likely corrupted or overwritten.")
            report.append("")
        
        # Display partitions
        for part in partitions:
            # Comment 1: Add "Corrupted Partition Entry" prefix if suspect flag is set
            prefix = "Corrupted Partition Entry - " if part.get('suspect', False) else ""
            report.append(f"{prefix}Partition {part['index']}:")
            report.append(f"  🚩 Bootable: {'Yes' if part['bootable'] else 'No'}")
            report.append(f"  📌 Type: 0x{part['type']:02X} ({part['type_name']})")
            
            # عرض نوع نظام الملفات المكتشف فعلياً مع درجات الثقة
            if part.get('filesystem_heuristics'):
                report.append("  🔍 Filesystem Auto-Heuristics:")
                for fs_det in part['filesystem_heuristics'][:3]:  # عرض أول 3 نتائج
                    confidence_bar = "█" * (fs_det['confidence'] // 10) + "░" * (10 - fs_det['confidence'] // 10)
                    report.append(f"     • {fs_det['type']}: {fs_det['confidence']}% confidence [{confidence_bar}]")
                    report.append(f"       {fs_det['description']}")
            elif part.get('detected_filesystem'):
                report.append(f"  🔍 Detected Filesystem: {part['detected_filesystem']} (from content analysis)")
                # إذا كان النوع المكتشف مختلف عن النوع المعلن
                if part['type'] in [0x6E, 0x74] or 'Unknown' in part['type_name']:
                    report.append(f"  ⚠️  Note: Partition type code (0x{part['type']:02X}) is unusual, but content analysis")
                    report.append(f"     indicates the actual filesystem is: {part['detected_filesystem']}")
            
            report.append(f"  📍 Start LBA: {part['start_lba']} (sector {part['start_lba']})")
            report.append(f"  📏 Size: {part['size_sectors']} sectors ({part['size_bytes']:,} bytes / {part['size_bytes']/(1024*1024):.2f} MB)")
            # Comment 2: Add "(invalid range)" suffix for invalid CHS
            chs_start_suffix = " (invalid range)" if part['invalid_chs'] else ""
            chs_end_suffix = " (invalid range)" if part['invalid_chs'] else ""
            report.append(f"  🔢 CHS Start: {part['start_chs']}{chs_start_suffix}")
            report.append(f"  🔢 CHS End: {part['end_chs']}{chs_end_suffix}")
            report.append("")
        
        # Anomaly detection
        report.append("🔍 Anomaly Detection:")
        report.append("-" * 80)
        
        anomalies = []
        
        # Track hard-failure conditions for Comment 1
        hard_failures = {}
        for part in partitions:
            hard_failures[part['index']] = []
        
        # Check for overlapping partitions
        for i, p1 in enumerate(partitions):
            for j, p2 in enumerate(partitions):
                if i >= j:
                    continue
                p1_end = p1['start_lba'] + p1['size_sectors']
                p2_end = p2['start_lba'] + p2['size_sectors']
                
                if not (p1_end <= p2['start_lba'] or p2_end <= p1['start_lba']):
                    anomalies.append(f"⚠️  Partitions {p1['index']} and {p2['index']} overlap!")
                    hard_failures[p1['index']].append("overlap")
                    hard_failures[p2['index']].append("overlap")
        
        # Comment 2: Check for invalid CHS values
        for part in partitions:
            if part['invalid_chs']:
                anomalies.append(f"⚠️  Partition {part['index']} has CHS values outside normal bounds (cylinder < 1024, head < 255, sector 1-63).")
                anomalies.append(f"    The partition table is likely corrupted at this entry.")
                hard_failures[part['index']].append("invalid_chs")
        
        # Comment 3: Enhanced LBA/size threshold checks
        for part in partitions:
            # Existing check: LBA 0
            if part['start_lba'] == 0 and part['type'] != 0:
                anomalies.append(f"⚠️  Partition {part['index']} starts at LBA 0 (suspicious)")
            
            # Comment 3: Check if start_lba itself is greater than max_lba
            if part['start_lba'] > max_lba:
                anomalies.append(f"⚠️  Partition {part['index']} start LBA ({part['start_lba']}) is outside the disk/file range (max: {max_lba})")
                hard_failures[part['index']].append("start_lba_out_of_range")
            
            # Existing check: extends beyond file size
            if part['start_lba'] + part['size_sectors'] > max_lba:
                anomalies.append(f"⚠️  Partition {part['index']} extends beyond file size")
                hard_failures[part['index']].append("extends_beyond_file_size")
            
            # Comment 3: Check if size_sectors is unusually large relative to disk
            if max_lba > 0:
                size_ratio = part['size_sectors'] / max_lba
                if size_ratio > 0.9:
                    anomalies.append(f"⚠️  Partition {part['index']} declared size ({part['size_sectors']} sectors) is unusually large")
                    anomalies.append(f"    relative to disk size ({max_lba} sectors, ratio: {size_ratio:.2%})")
                    hard_failures[part['index']].append("unusually_large_size")
            
            # Comment 3: Check absolute threshold
            if part['start_lba'] > LBA_SUSPICIOUS_THRESHOLD or part['size_sectors'] > LBA_SUSPICIOUS_THRESHOLD:
                anomalies.append(f"⚠️  Partition {part['index']} has unusually high LBA values (start: {part['start_lba']}, size: {part['size_sectors']})")
                anomalies.append(f"    These values exceed typical MBR setup thresholds")
                hard_failures[part['index']].append("exceeds_absolute_threshold")
        
        # Comment 1: Global sanity evaluation - mark partitions with hard failures as suspect
        for part in partitions:
            if hard_failures[part['index']]:
                part['suspect'] = True
        
        # Comment 1: Count partitions with hard failures
        partitions_with_failures = sum(1 for part in partitions if hard_failures[part['index']])
        total_non_empty = len(partitions)
        
        # Comment 1 & 4: If most/all partitions have hard failures, mark table as corrupt
        if total_non_empty > 0:
            failure_ratio = partitions_with_failures / total_non_empty
            if failure_ratio >= 0.75 or (partitions_with_failures >= 3 and total_non_empty >= 4):
                report.append("")
                report.append("❌ CRITICAL: MBR Partition Table Corruption Detected")
                report.append("-" * 80)
                report.append(f"The partition table appears to be corrupt or invalid for this image.")
                report.append(f"{partitions_with_failures} out of {total_non_empty} partition entries have severe anomalies")
                report.append(f"(extends beyond file size, start LBA outside disk range, invalid CHS, or overlaps).")
                report.append("These entries should be treated as garbage data rather than trusted partition definitions.")
                report.append("")
        
        # Check for hidden partitions (type 0x05, 0x0F, 0x85)
        hidden_types = [0x05, 0x0F, 0x85]
        for part in partitions:
            if part['type'] in hidden_types:
                anomalies.append(f"⚠️  Partition {part['index']} has hidden/extended partition type (0x{part['type']:02X})")
        
        # Check boot code for modifications (all zeros or all same byte is suspicious)
        if boot_code == b'\x00' * len(boot_code):
            anomalies.append("⚠️  Boot code is all zeros (may be wiped)")
        elif len(set(boot_code)) == 1:
            anomalies.append("⚠️  Boot code contains only one byte value (suspicious)")
        
        # Malware Detection
        malware_indicators = self.detect_malware_patterns(boot_code)
        if malware_indicators:
            report.append("")
            report.append("🛡️  Malware Detection:")
            report.append("-" * 80)
            for indicator in malware_indicators:
                severity_icon = "🔴" if indicator['severity'] == 'High' else "🟡"
                report.append(f"{severity_icon} {indicator['type']} ({indicator['severity']} severity)")
                report.append(f"   {indicator['description']}")
            report.append("")
        
        # Encryption Detection
        enc_result, entropy = self.detect_encryption(boot_code)
        if enc_result:
            report.append("🔐 Encryption Analysis:")
            report.append("-" * 80)
            report.append(f"⚠️  {enc_result}")
            report.append(f"   Entropy: {entropy:.2f}/8.0")
            report.append("")
        
        # Comment 4: Improve wording for corruption vs unusual layouts
        if anomalies:
            # Check for patterns indicating corruption
            corruption_indicators = [
                "extends beyond file size",
                "start LBA outside the disk/file range",
                "CHS values outside normal bounds"
            ]
            
            corruption_count = sum(1 for a in anomalies if any(indicator in a for indicator in corruption_indicators))
            overlap_count = sum(1 for a in anomalies if "overlap" in a)
            
            # Comment 4: Add summarizing line when corruption patterns detected
            if corruption_count > 0 and len(partitions) > 0:
                if corruption_count >= len(partitions):
                    report.append("⚠️  Multiple severe anomalies detected across all partitions, indicating")
                    report.append("    partition table corruption rather than merely unusual layout.")
                    report.append("")
            
            # Comment 4: Clarify overlaps as corruption symptom when appearing in clusters
            if overlap_count >= 2:
                report.append("⚠️  Multiple overlapping partitions detected - this pattern indicates")
                report.append("    partition table corruption, not a valid but unusual layout.")
                report.append("")
            
            for anomaly in anomalies:
                report.append(anomaly)
        else:
            report.append("✅ No obvious anomalies detected")
        
        # Comment 4: Optional explanatory paragraph at end of MBR section
        if partitions_with_failures > 0 and failure_ratio >= 0.5:
            report.append("")
            report.append("📝 Summary:")
            report.append("   Due to the multiple severe anomalies detected (invalid LBA ranges, CHS corruption,")
            report.append("   overlaps, or sizes exceeding disk capacity), the partition entries should be")
            report.append("   treated as corrupted data rather than trusted partition definitions.")
            report.append("   The raw hex and numeric values are preserved above for forensic examination,")
            report.append("   but should not be used for partition recovery without additional validation.")
        
        # Expected vs Found Validation Table
        report.append("")
        report.append("📊 Expected vs Found Validation Table:")
        report.append("-" * 80)
        report.append(f"{'Field':<30} {'Expected':<25} {'Found':<25} {'Status':<15}")
        report.append("-" * 80)
        
        # MBR Signature validation
        mbr_sig = struct.unpack('<H', self.data[510:512])[0] if len(self.data) >= 512 else 0
        sig_status = "✅ VALID" if mbr_sig == 0xAA55 else "❌ INVALID"
        report.append(f"{'MBR Signature (0x55AA)':<30} {'0xAA55':<25} {hex(mbr_sig):<25} {sig_status:<15}")
        
        # Boot Code validation
        boot_code_entropy = self.calculate_entropy(boot_code) if boot_code else 0
        boot_code_status = "⚠️  HIGH ENTROPY" if boot_code_entropy > 7.5 else "✅ NORMAL"
        report.append(f"{'Boot Code Entropy':<30} {'< 7.5':<25} {f'{boot_code_entropy:.2f}':<25} {boot_code_status:<15}")
        
        # Partition table validation
        for part in partitions:
            # CHS validation
            chs_status = "✅ VALID" if not part['invalid_chs'] else "⚠️  OUT OF RANGE"
            report.append(f"{'Partition ' + str(part['index']) + ' CHS':<30} {'C<1024, H<255, S=1-63':<25} {'See details above':<25} {chs_status:<15}")
            
            # LBA validation
            lba_status = "✅ VALID" if part['start_lba'] <= max_lba else "⚠️  OUT OF RANGE"
            report.append(f"{'Partition ' + str(part['index']) + ' Start LBA':<30} {f'< {max_lba}':<25} {str(part['start_lba']):<25} {lba_status:<15}")
        
        report.append("")
        
        # إجابات الأسئلة العملية
        report.append(self.answer_mbr_questions(partitions, boot_code))
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def answer_mbr_questions(self, partitions, boot_code):
        """إجابة على أسئلة الاختبار العملي لـ MBR"""
        answers = []
        answers.append("=" * 80)
        answers.append("📝 إجابات الأسئلة العملية - MBR (Practical Exam Answers)")
        answers.append("=" * 80)
        answers.append("")
        
        if not partitions:
            answers.append("⚠️  لا توجد بارتشنات للتحليل")
            return "\n".join(answers)
        
        # سؤال: عدد البارتشنات
        answers.append(f"✅ عدد البارتشنات الموجودة: {len(partitions)}")
        
        # سؤال: نوع كل بارتشن
        answers.append("")
        answers.append("📌 أنواع البارتشنات:")
        for part in partitions:
            type_info = f"Partition {part['index']}: 0x{part['type']:02X} ({part['type_name']})"
            # إضافة معلومات نوع نظام الملفات المكتشف فعلياً
            if part.get('detected_filesystem'):
                type_info += f" → Actual FS: {part['detected_filesystem']}"
            answers.append(f"   {type_info}")
        
        # سؤال: البارتشن القابل للـ boot
        bootable_parts = [p for p in partitions if p['bootable']]
        if bootable_parts:
            answers.append("")
            answers.append(f"🚩 البارتشن القابل للـ boot: Partition {bootable_parts[0]['index']}")
        else:
            answers.append("")
            answers.append("🚩 لا يوجد بارتشن قابل للـ boot")
        
        # سؤال: حجم كل بارتشن
        answers.append("")
        answers.append("📏 أحجام البارتشنات:")
        for part in partitions:
            answers.append(f"   Partition {part['index']}: {part['size_sectors']} sectors ({part['size_bytes']/(1024*1024):.2f} MB)")
        
        # سؤال: Start LBA لكل بارتشن
        answers.append("")
        answers.append("📍 Start LBA لكل بارتشن:")
        for part in partitions:
            answers.append(f"   Partition {part['index']}: LBA {part['start_lba']}")
        
        # سؤال: CHS values
        answers.append("")
        answers.append("🔢 قيم CHS:")
        for part in partitions:
            answers.append(f"   Partition {part['index']}: Start CHS: {part['start_chs']}, End CHS: {part['end_chs']}")
        
        # سؤال: Boot code signature
        if len(boot_code) >= 2:
            boot_sig = struct.unpack('<H', boot_code[-2:])[0] if len(boot_code) >= 2 else 0
            answers.append("")
            answers.append(f"🔐 Boot Code Signature: 0x{boot_sig:04X}")
        
        return "\n".join(answers)
    
    def get_partition_type_name(self, ptype):
        """ديه بترجع اسم نوع البارتشن - كل رقم له معنى"""
        types = {
            0x00: "Empty",
            0x01: "FAT12",
            0x04: "FAT16 <32MB",
            0x05: "Extended (CHS)",
            0x06: "FAT16",
            0x07: "NTFS/HPFS",
            0x0B: "FAT32 (CHS)",
            0x0C: "FAT32 (LBA)",
            0x0E: "FAT16 (LBA)",
            0x0F: "Extended (LBA)",
            0x11: "Hidden FAT12",
            0x14: "Hidden FAT16 <32MB",
            0x16: "Hidden FAT16",
            0x17: "Hidden HPFS/NTFS",
            0x1B: "Hidden FAT32",
            0x1C: "Hidden FAT32 (LBA)",
            0x1E: "Hidden FAT16 (LBA)",
            0x82: "Linux Swap",
            0x83: "Linux",
            0x85: "Linux Extended",
            0xEE: "GPT Protective",
            0xEF: "EFI System Partition",
            # أنواع إضافية شائعة
            0x27: "NTFS (Windows RE)",
            0x42: "Microsoft MBR",
            0x63: "Unix System V",
            0x64: "PC-ARMOUR",
            0x65: "Novell Netware",
            0x6E: "Possible FAT32/NTFS (Custom/Unknown)",
            0x74: "Possible FAT32/NTFS (Scramdisk/Custom)",
            0x80: "Minix",
            0x81: "Linux",
            0x82: "Linux Swap",
            0x83: "Linux",
            0x84: "OS/2 hidden C: drive",
            0x85: "Linux Extended",
            0x86: "NTFS Volume Set",
            0x87: "NTFS Volume Set",
            0x93: "Amoeba",
            0x94: "Amoeba BBT",
            0xA5: "FreeBSD",
            0xA6: "OpenBSD",
            0xA7: "NeXTSTEP",
            0xA8: "Darwin UFS",
            0xA9: "NetBSD",
            0xAB: "Darwin boot",
            0xAF: "HFS / HFS+",
            0xB7: "BSDI fs",
            0xB8: "BSDI swap",
            0xBE: "Solaris boot",
            0xBF: "Solaris",
            0xC1: "DRDOS/sec (FAT-12)",
            0xC4: "DRDOS/sec (FAT-16 < 32M)",
            0xC6: "DRDOS/sec (FAT-16)",
            0xC7: "Syrinx",
            0xDA: "Non-FS data",
            0xDB: "CP/M / CTOS",
            0xDE: "Dell Utility",
            0xDF: "BootIt",
            0xE1: "DOS access",
            0xE3: "DOS R/O",
            0xE4: "DOS secondary",
            0xEB: "BeOS fs",
            0xEE: "EFI GPT",
            0xEF: "EFI (FAT-12/16/32)",
            0xF0: "Linux/PA-RISC boot",
            0xF1: "SpeedStor",
            0xF4: "SpeedStor",
            0xF2: "DOS secondary",
            0xFB: "VMware VMFS",
            0xFC: "VMware VMKCORE",
            0xFD: "Linux raid autodetect",
            0xFE: "LANstep",
            0xFF: "BBT"
        }
        return types.get(ptype, f"Unknown (0x{ptype:02X})")
    
    def detect_filesystem_heuristics(self, start_lba, size_sectors):
        """الكشف التلقائي المتقدم لأنظمة الملفات مع درجات الثقة"""
        if not self.data:
            return []
        
        # حساب offset البارتشن
        partition_offset = start_lba * 512
        
        # التأكد من أن البارتشن موجود في البيانات
        if partition_offset >= self.file_size:
            return []
        
        # قراءة أول 8192 بايت للتحليل
        read_size = min(8192, self.file_size - partition_offset)
        boot_sector = self.read_at_offset(partition_offset, read_size)
        
        if len(boot_sector) < 512:
            return []
        
        filesystem_detections = []
        
        # 1. NTFS Detection
        ntfs_confidence = 0
        if len(boot_sector) >= 11:
            ntfs_signature = boot_sector[3:11]
            if ntfs_signature == b'NTFS    ':
                ntfs_confidence = 100
            elif b'NTFS' in boot_sector[:512]:
                ntfs_confidence = 60
        
        if ntfs_confidence > 0:
            filesystem_detections.append({
                'type': 'NTFS',
                'confidence': ntfs_confidence,
                'description': 'NTFS filesystem detected'
            })
        
        # 2. FAT32 Detection
        fat32_confidence = 0
        if len(boot_sector) >= 90:
            fat32_label = boot_sector[82:90].strip()
            if b'FAT32' in fat32_label:
                if boot_sector[510:512] == b'\x55\xAA':
                    fat32_confidence = 100
                else:
                    fat32_confidence = 70
            elif b'FAT' in fat32_label and boot_sector[510:512] == b'\x55\xAA':
                # قد يكون FAT32 أو FAT16
                try:
                    sectors_per_fat_32 = struct.unpack('<I', boot_sector[36:40])[0]
                    if sectors_per_fat_32 > 0:
                        fat32_confidence = 85
                except:
                    pass
        
        if fat32_confidence > 0:
            filesystem_detections.append({
                'type': 'FAT32',
                'confidence': fat32_confidence,
                'description': 'FAT32 filesystem detected'
            })
        
        # 3. FAT16 Detection
        fat16_confidence = 0
        if len(boot_sector) >= 90 and boot_sector[510:512] == b'\x55\xAA':
            fat_label = boot_sector[54:62].strip()
            if b'FAT' in fat_label and b'FAT32' not in boot_sector[82:90]:
                try:
                    sectors_per_fat_16 = struct.unpack('<H', boot_sector[22:24])[0]
                    if sectors_per_fat_16 > 0:
                        fat16_confidence = 90
                    else:
                        fat16_confidence = 60
                except:
                    fat16_confidence = 50
        
        if fat16_confidence > 0:
            filesystem_detections.append({
                'type': 'FAT16',
                'confidence': fat16_confidence,
                'description': 'FAT16 filesystem detected'
            })
        
        # 4. FAT12 Detection
        fat12_confidence = 0
        if boot_sector[510:512] == b'\x55\xAA':
            try:
                bytes_per_sector = struct.unpack('<H', boot_sector[11:13])[0]
                total_sectors_16 = struct.unpack('<H', boot_sector[19:21])[0]
                if bytes_per_sector in [512, 1024, 2048, 4096] and total_sectors_16 < 65536:
                    fat12_confidence = 70
            except:
                pass
        
        if fat12_confidence > 0:
            filesystem_detections.append({
                'type': 'FAT12',
                'confidence': fat12_confidence,
                'description': 'FAT12 filesystem (possible)'
            })
        
        # 5. exFAT Detection
        exfat_confidence = 0
        if len(boot_sector) >= 12:
            exfat_signature = boot_sector[3:11]
            if exfat_signature == b'EXFAT   ':
                exfat_confidence = 100
            elif b'exFAT' in boot_sector[:512] or b'EXFAT' in boot_sector[:512]:
                exfat_confidence = 60
        
        if exfat_confidence > 0:
            filesystem_detections.append({
                'type': 'exFAT',
                'confidence': exfat_confidence,
                'description': 'exFAT filesystem detected'
            })
        
        # 6. EXT2/EXT3/EXT4 Detection
        ext_confidence = 0
        if len(boot_sector) >= 2:
            ext_signature = struct.unpack('<H', boot_sector[56:58])[0]
            if ext_signature == 0xEF53:  # EXT2/3/4 magic number
                ext_confidence = 95
                # محاولة التمييز بين EXT2/3/4
                if len(boot_sector) >= 88:
                    feature_incompat = struct.unpack('<I', boot_sector[64:68])[0]
                    if feature_incompat & 0x04:  # EXT4 feature
                        ext_type = 'EXT4'
                    elif feature_incompat & 0x02:  # EXT3 feature
                        ext_type = 'EXT3'
                    else:
                        ext_type = 'EXT2'
                else:
                    ext_type = 'EXT2/3/4'
                
                filesystem_detections.append({
                    'type': ext_type,
                    'confidence': ext_confidence,
                    'description': f'{ext_type} filesystem detected'
                })
        
        # 7. HFS+ Detection
        hfs_confidence = 0
        if len(boot_sector) >= 2:
            hfs_signature = struct.unpack('>H', boot_sector[0:2])[0]
            if hfs_signature == 0x4244:  # HFS+ signature
                hfs_confidence = 95
            elif b'HFS+' in boot_sector[:512] or b'HFS ' in boot_sector[:512]:
                hfs_confidence = 60
        
        if hfs_confidence > 0:
            filesystem_detections.append({
                'type': 'HFS+',
                'confidence': hfs_confidence,
                'description': 'HFS+ filesystem detected'
            })
        
        # 8. ISO9660 Detection
        iso_confidence = 0
        if len(boot_sector) >= 8:
            iso_signature = boot_sector[1:8]
            if iso_signature == b'CD001\x01':
                iso_confidence = 100
            elif b'CD001' in boot_sector[:512]:
                iso_confidence = 80
        
        if iso_confidence > 0:
            filesystem_detections.append({
                'type': 'ISO9660',
                'confidence': iso_confidence,
                'description': 'ISO9660 filesystem detected'
            })
        
        # ترتيب حسب الثقة
        filesystem_detections.sort(key=lambda x: x['confidence'], reverse=True)
        
        return filesystem_detections
    
    def detect_filesystem_from_content(self, start_lba, size_sectors):
        """التحقق من نوع نظام الملفات الفعلي من محتوى البارتشن (للتوافق مع الكود القديم)"""
        detections = self.detect_filesystem_heuristics(start_lba, size_sectors)
        if detections and detections[0]['confidence'] >= 70:
            return detections[0]['type']
        return None
    
    def analyze_gpt(self):
        """تحليل GPT - هنا بنستخرج header و partition entries"""
        report = []
        report.append("=" * 80)
        report.append("تحليل GPT (GUID Partition Table)")
        report.append("=" * 80)
        report.append("")
        
        if len(self.data) < 1024:
            report.append("❌ الملف صغير جداً - GPT يحتاج على الأقل 1024 بايت (LBA 0 + LBA 1)")
            return "\n".join(report)
        
        # Parse GPT Header (starts at LBA 1 = offset 512)
        # GPT header signature: "EFI PART" at offset 512
        gpt_header_data = self.read_at_offset(512, 512)
        
        if len(gpt_header_data) < 92:
            report.append("❌ لا يمكن قراءة GPT Header")
            return "\n".join(report)
        
        if gpt_header_data[0:8] != b'EFI PART':
            report.append("⚠️  GPT signature not found at LBA 1 (offset 512)")
            report.append("   Searching for GPT header...")
            # البحث في أماكن أخرى
            found_gpt = False
            for offset in range(512, min(8192, self.file_size), 512):
                test_data = self.read_at_offset(offset, 8)
                if test_data == b'EFI PART':
                    report.append(f"   Found GPT signature at offset {offset}")
                    gpt_header_data = self.read_at_offset(offset, 512)
                    found_gpt = True
                    break
            if not found_gpt:
                report.append("❌ GPT signature not found")
                return "\n".join(report)
        
        # Parse Protective MBR في LBA 0
        protective_mbr = self.read_at_offset(0, 512)
        if len(protective_mbr) >= 512:
            mbr_sig = struct.unpack('<H', protective_mbr[510:512])[0]
            if mbr_sig == 0xAA55:
                # التحقق من Partition Type في Protective MBR
                partition_type = protective_mbr[450]  # Byte 4 of first partition entry
                if partition_type == 0xEE:
                    report.append("✅ Protective MBR found at LBA 0 (GPT disk)")
                    report.append("")
                else:
                    report.append("⚠️  MBR found at LBA 0, but partition type is not 0xEE (GPT Protective)")
                    report.append("")
        
        # GPT Header Structure (bytes 0-91 within the 512-byte sector at LBA 1)
        # Offset 0-7: Signature "EFI PART"
        signature = gpt_header_data[0:8]
        # Offset 8-11: Revision (usually 0x00010000)
        revision = struct.unpack('<I', gpt_header_data[8:12])[0]
        # Offset 12-15: Header size (usually 92)
        header_size = struct.unpack('<I', gpt_header_data[12:16])[0]
        # Offset 16-19: CRC32 of header
        header_crc32 = struct.unpack('<I', gpt_header_data[16:20])[0]
        # Offset 20-23: Reserved (must be 0)
        # Offset 24-31: Current LBA (location of this header)
        current_lba = struct.unpack('<Q', gpt_header_data[24:32])[0]
        # Offset 32-39: Backup LBA (location of backup header)
        backup_lba = struct.unpack('<Q', gpt_header_data[32:40])[0]
        # Offset 40-47: First usable LBA
        first_usable_lba = struct.unpack('<Q', gpt_header_data[40:48])[0]
        # Offset 48-55: Last usable LBA
        last_usable_lba = struct.unpack('<Q', gpt_header_data[48:56])[0]
        # Offset 56-71: Disk GUID
        disk_guid = gpt_header_data[56:72]
        # Offset 72-79: Partition entry LBA (start of partition entry array)
        partition_entry_lba = struct.unpack('<Q', gpt_header_data[72:80])[0]
        # Offset 80-83: Number of partition entries
        num_partition_entries = struct.unpack('<I', gpt_header_data[80:84])[0]
        # Offset 84-87: Size of each partition entry (usually 128)
        partition_entry_size = struct.unpack('<I', gpt_header_data[84:88])[0]
        # Offset 88-91: CRC32 of partition entry array
        partition_array_crc32 = struct.unpack('<I', gpt_header_data[88:92])[0]
        
        report.append("📋 GPT Header Information:")
        report.append("-" * 80)
        report.append(f"Signature: {signature.decode('ascii', errors='ignore')}")
        report.append(f"Revision: 0x{revision:08X}")
        report.append(f"Header Size: {header_size} bytes")
        report.append(f"Header CRC32: 0x{header_crc32:08X}")
        report.append(f"Current LBA: {current_lba}")
        report.append(f"Backup LBA: {backup_lba}")
        report.append(f"First Usable LBA: {first_usable_lba}")
        report.append(f"Last Usable LBA: {last_usable_lba}")
        report.append(f"Disk GUID: {self.format_guid(disk_guid)}")
        report.append(f"Partition Entry Array LBA: {partition_entry_lba}")
        report.append(f"Number of Partition Entries: {num_partition_entries}")
        report.append(f"Partition Entry Size: {partition_entry_size} bytes")
        report.append(f"Partition Array CRC32: 0x{partition_array_crc32:08X}")
        report.append("")
        
        # Validate Primary GPT Header CRC32
        header_for_crc = bytearray(gpt_header_data[0:header_size])
        struct.pack_into('<I', header_for_crc, 16, 0)  # Zero out CRC field
        calculated_crc = zlib.crc32(header_for_crc) & 0xFFFFFFFF
        
        primary_crc_valid = (calculated_crc == header_crc32)
        if primary_crc_valid:
            report.append("✅ Primary GPT Header CRC32: VALID")
        else:
            report.append(f"⚠️  Primary GPT Header CRC32: INVALID (calculated: 0x{calculated_crc:08X}, stored: 0x{header_crc32:08X})")
        report.append("")
        
        # Calculate Partition Entry Array offset
        partition_array_offset = partition_entry_lba * 512
        
        # Validate Partition Entry Array CRC32
        partition_array_size = num_partition_entries * partition_entry_size
        if partition_array_offset + partition_array_size <= self.file_size:
            partition_array_data = self.read_at_offset(partition_array_offset, partition_array_size)
            if len(partition_array_data) == partition_array_size:
                calculated_array_crc = zlib.crc32(partition_array_data) & 0xFFFFFFFF
                array_crc_valid = (calculated_array_crc == partition_array_crc32)
                if array_crc_valid:
                    report.append("✅ Partition Entry Array CRC32: VALID")
                else:
                    report.append(f"⚠️  Partition Entry Array CRC32: INVALID (calculated: 0x{calculated_array_crc:08X}, stored: 0x{partition_array_crc32:08X})")
                report.append("")
        
        # Try to find backup header (at backup_lba or last LBA)
        backup_header_found = False
        backup_header_valid = False
        
        # First try the specified backup_lba
        if backup_lba > 0:
            backup_offset = backup_lba * 512
            if backup_offset + 512 <= self.file_size:
                backup_data = self.read_at_offset(backup_offset, 512)
                if len(backup_data) >= 512 and backup_data[0:8] == b'EFI PART':
                    backup_header_found = True
                    backup_header_crc32 = struct.unpack('<I', backup_data[16:20])[0]
                    backup_header_for_crc = bytearray(backup_data[0:header_size])
                    struct.pack_into('<I', backup_header_for_crc, 16, 0)
                    backup_calculated_crc = zlib.crc32(backup_header_for_crc) & 0xFFFFFFFF
                    backup_header_valid = (backup_calculated_crc == backup_header_crc32)
        
        # Also try last LBA (common location for backup GPT)
        if not backup_header_found:
            last_lba = (self.file_size // 512) - 1
            if last_lba > 0:
                last_lba_offset = last_lba * 512
                if last_lba_offset + 512 <= self.file_size:
                    backup_data = self.read_at_offset(last_lba_offset, 512)
                    if len(backup_data) >= 512 and backup_data[0:8] == b'EFI PART':
                        backup_header_found = True
                        backup_lba = last_lba
                        backup_offset = last_lba_offset
                        backup_header_crc32 = struct.unpack('<I', backup_data[16:20])[0]
                        backup_header_for_crc = bytearray(backup_data[0:header_size])
                        struct.pack_into('<I', backup_header_for_crc, 16, 0)
                        backup_calculated_crc = zlib.crc32(backup_header_for_crc) & 0xFFFFFFFF
                        backup_header_valid = (backup_calculated_crc == backup_header_crc32)
        
        if backup_header_found:
            report.append("📋 Backup GPT Header Found:")
            report.append(f"   Location: LBA {backup_lba} (offset {backup_offset:,} bytes)")
            if backup_header_valid:
                report.append("✅ Backup GPT Header CRC32: VALID")
            else:
                report.append(f"⚠️  Backup GPT Header CRC32: INVALID (calculated: 0x{backup_calculated_crc:08X}, stored: 0x{backup_header_crc32:08X})")
            
            # Compare primary and backup headers
            if not primary_crc_valid and backup_header_valid:
                report.append("⚠️  GPT header mismatch (primary invalid, backup valid) - possible manipulation or corruption")
            elif primary_crc_valid and not backup_header_valid:
                report.append("⚠️  GPT header mismatch (primary valid, backup invalid) - possible backup corruption")
            elif not primary_crc_valid and not backup_header_valid:
                report.append("⚠️  Both GPT headers invalid - severe corruption detected")
            
            report.append("")
        else:
            report.append("⚠️  Backup GPT Header: NOT FOUND")
            report.append("   (Expected at LBA specified in primary header or last LBA)")
            report.append("")
        
        # Parse Partition Entry Array
        # Usually starts at LBA 2 (1024 bytes offset)
        # Note: partition_array_offset already calculated above
        if partition_array_offset >= self.file_size:
            report.append("⚠️  Partition entry array beyond file size")
            report.append("=" * 80)
            return "\n".join(report)
        
        report.append("📋 Partition Entries:")
        report.append("-" * 80)
        
        partitions = []
        deleted_count = 0
        
        for i in range(num_partition_entries):
            entry_offset = partition_array_offset + (i * partition_entry_size)
            if entry_offset + partition_entry_size > self.file_size:
                break
            
            entry = self.read_at_offset(entry_offset, partition_entry_size)
            
            # Partition Entry Structure (128 bytes typically)
            # Offset 0-15: Partition type GUID
            partition_type_guid = entry[0:16]
            # Offset 16-31: Unique partition GUID
            partition_guid = entry[16:32]
            # Offset 32-39: Starting LBA
            start_lba = struct.unpack('<Q', entry[32:40])[0]
            # Offset 40-47: Ending LBA
            end_lba = struct.unpack('<Q', entry[40:48])[0]
            # Offset 48-55: Attributes
            attributes = struct.unpack('<Q', entry[48:56])[0]
            # Offset 56-127: Partition name (UTF-16LE, null-terminated)
            name_bytes = entry[56:128]
            # Find null terminator
            name_end = name_bytes.find(b'\x00\x00')
            if name_end != -1:
                name_bytes = name_bytes[:name_end+1]
            try:
                partition_name = name_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
            except:
                partition_name = "<Invalid UTF-16>"
            
            # Check if partition is used (non-zero type GUID)
            is_deleted = partition_type_guid == b'\x00' * 16
            
            if not is_deleted:
                partition_info = {
                    'index': i + 1,
                    'type_guid': partition_type_guid,
                    'partition_guid': partition_guid,
                    'start_lba': start_lba,
                    'end_lba': end_lba,
                    'size_sectors': end_lba - start_lba + 1,
                    'attributes': attributes,
                    'name': partition_name,
                    'is_deleted': False
                }
                partitions.append(partition_info)
            else:
                deleted_count += 1
        
        # Display partitions
        for part in partitions:
            report.append(f"Partition {part['index']}: {part['name']}")
            type_guid_formatted = self.format_guid(part['type_guid'])
            report.append(f"  🆔 Partition Type GUID: {type_guid_formatted}")
            
            # تحديد نوع البارتشن من GUID
            known_guids = {
                "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition (ESP)",
                "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved Partition",
                "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data Partition",
                "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery Environment",
            }
            if type_guid_formatted.upper() in known_guids:
                report.append(f"     → Type: {known_guids[type_guid_formatted.upper()]}")
            
            report.append(f"  🆔 Unique Partition GUID: {self.format_guid(part['partition_guid'])}")
            report.append(f"  📍 Start LBA: {part['start_lba']}")
            report.append(f"  📍 End LBA: {part['end_lba']}")
            report.append(f"  📏 Size: {part['size_sectors']} sectors ({part['size_sectors']*512:,} bytes / {part['size_sectors']*512/(1024*1024):.2f} MB)")
            report.append(f"  🔐 Attributes: 0x{part['attributes']:016X}")
            if part['attributes'] & 0x1:
                report.append("     - System Partition (Required)")
            if part['attributes'] & 0x2:
                report.append("     - EFI Ignore")
            if part['attributes'] & 0x4:
                report.append("     - Legacy BIOS Bootable")
            report.append("")
        
        if deleted_count > 0:
            report.append(f"🗑️  Deleted/Empty Partitions Found: {deleted_count}")
            report.append("")
        
        # Anomaly detection
        report.append("🔍 Anomaly Detection:")
        report.append("-" * 80)
        
        anomalies = []
        
        # Check for overlapping partitions
        for i, p1 in enumerate(partitions):
            for j, p2 in enumerate(partitions):
                if i >= j:
                    continue
                if not (p1['end_lba'] < p2['start_lba'] or p2['end_lba'] < p1['start_lba']):
                    anomalies.append(f"⚠️  Partitions {p1['index']} and {p2['index']} overlap!")
        
        # Check for partitions outside usable range
        for part in partitions:
            if part['start_lba'] < first_usable_lba or part['end_lba'] > last_usable_lba:
                anomalies.append(f"⚠️  Partition {part['index']} outside usable LBA range")
        
        if anomalies:
            for anomaly in anomalies:
                report.append(anomaly)
        else:
            report.append("✅ No obvious anomalies detected")
        
        report.append("")
        
        # إجابات الأسئلة العملية
        report.append(self.answer_gpt_questions(partitions, disk_guid, first_usable_lba, last_usable_lba))
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def answer_gpt_questions(self, partitions, disk_guid, first_usable_lba, last_usable_lba):
        """إجابة على أسئلة الاختبار العملي لـ GPT"""
        answers = []
        answers.append("=" * 80)
        answers.append("📝 إجابات الأسئلة العملية - GPT (Practical Exam Answers)")
        answers.append("=" * 80)
        answers.append("")
        
        # سؤال: عدد البارتشنات المدعومة
        answers.append("✅ عدد البارتشنات المدعومة في GPT: 128")
        
        # سؤال: Disk GUID
        answers.append("")
        answers.append(f"🆔 Disk GUID: {self.format_guid(disk_guid)}")
        
        # سؤال: عدد البارتشنات الموجودة
        answers.append("")
        answers.append(f"✅ عدد البارتشنات الموجودة: {len(partitions)}")
        
        if partitions:
            # سؤال: أسماء البارتشنات
            answers.append("")
            answers.append("📌 أسماء البارتشنات:")
            for part in partitions:
                answers.append(f"   Partition {part['index']}: {part['name']}")
            
            # سؤال: Partition Type GUIDs (مهم جداً للأسئلة)
            answers.append("")
            answers.append("🆔 Partition Type GUIDs:")
            for part in partitions:
                type_guid = self.format_guid(part.get('type_guid', b'\x00' * 16))
                answers.append(f"   Partition {part['index']}: {type_guid}")
                # تحديد نوع البارتشن من GUID
                known_guids = {
                    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition (ESP)",
                    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved Partition",
                    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data Partition",
                    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery Environment",
                }
                if type_guid.upper() in known_guids:
                    answers.append(f"      → Type: {known_guids[type_guid.upper()]}")
            
            # سؤال: Unique Partition GUIDs
            answers.append("")
            answers.append("🆔 Unique Partition GUIDs:")
            for part in partitions:
                answers.append(f"   Partition {part['index']}: {self.format_guid(part['partition_guid'])}")
            
            # سؤال: Start/End LBA
            answers.append("")
            answers.append("📍 Start/End LBA لكل بارتشن:")
            for part in partitions:
                answers.append(f"   Partition {part['index']}: Start LBA {part['start_lba']}, End LBA {part['end_lba']}")
            
            # سؤال: أحجام البارتشنات
            answers.append("")
            answers.append("📏 أحجام البارتشنات:")
            for part in partitions:
                answers.append(f"   Partition {part['index']}: {part['size_sectors']} sectors ({part['size_sectors']*512/(1024*1024):.2f} MB)")
        
        # سؤال: Usable LBA range
        answers.append("")
        answers.append(f"📊 Usable LBA Range: {first_usable_lba} - {last_usable_lba}")
        
        return "\n".join(answers)
    
    def format_guid(self, guid_bytes):
        """ديه بتحول GUID من bytes لصيغة مقروءة (Mixed Endian Format)"""
        if len(guid_bytes) != 16:
            return "<Invalid GUID>"
        
        # GPT GUIDs are stored in mixed endian format:
        # - First 4 bytes: little-endian
        # - Next 2 bytes: little-endian
        # - Next 2 bytes: little-endian
        # - Next 2 bytes: big-endian
        # - Last 6 bytes: big-endian
        
        # Extract parts
        part1 = struct.unpack('<I', guid_bytes[0:4])[0]  # Little-endian
        part2 = struct.unpack('<H', guid_bytes[4:6])[0]   # Little-endian
        part3 = struct.unpack('<H', guid_bytes[6:8])[0]   # Little-endian
        part4 = struct.unpack('>H', guid_bytes[8:10])[0]  # Big-endian
        part5 = struct.unpack('>Q', b'\x00\x00' + guid_bytes[10:16])[0] & 0xFFFFFFFFFFFF  # Big-endian (6 bytes)
        
        # Format as GUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        return f"{part1:08X}-{part2:04X}-{part3:04X}-{part4:04X}-{part5:012X}"
    
    def analyze_fat32(self):
        """تحليل FAT32 - هنا بنستخرج BPB و معلومات الملفات"""
        report = []
        report.append("=" * 80)
        report.append("تحليل FAT32 Filesystem")
        report.append("=" * 80)
        report.append("")
        
        if len(self.data) < 512:
            report.append("❌ الملف صغير جداً")
            return "\n".join(report)
        
        # Parse BPB (BIOS Parameter Block)
        # Offset 0-2: Jump instruction
        jump_instruction = self.data[0:3]
        # Offset 3-10: OEM name
        oem_name = self.data[3:11].decode('ascii', errors='ignore').strip()
        # Offset 11-12: Bytes per sector
        bytes_per_sector = struct.unpack('<H', self.data[11:13])[0]
        # Offset 13: Sectors per cluster
        sectors_per_cluster = self.data[13]
        # Offset 14-15: Reserved sectors
        reserved_sectors = struct.unpack('<H', self.data[14:16])[0]
        # Offset 16: Number of FATs
        num_fats = self.data[16]
        # Offset 17-18: Root directory entries (0 for FAT32)
        root_dir_entries = struct.unpack('<H', self.data[17:19])[0]
        # Offset 19-20: Total sectors (16-bit, 0 if 32-bit used)
        total_sectors_16 = struct.unpack('<H', self.data[19:21])[0]
        # Offset 21: Media descriptor
        media_descriptor = self.data[21]
        # Offset 22-23: Sectors per FAT (16-bit, 0 for FAT32)
        sectors_per_fat_16 = struct.unpack('<H', self.data[22:24])[0]
        # Offset 24-25: Sectors per track
        sectors_per_track = struct.unpack('<H', self.data[24:26])[0]
        # Offset 26-27: Number of heads
        num_heads = struct.unpack('<H', self.data[26:28])[0]
        # Offset 28-31: Hidden sectors
        hidden_sectors = struct.unpack('<I', self.data[28:32])[0]
        # Offset 32-35: Total sectors (32-bit)
        total_sectors_32 = struct.unpack('<I', self.data[32:36])[0]
        # Offset 36-39: Sectors per FAT (32-bit for FAT32)
        sectors_per_fat_32 = struct.unpack('<I', self.data[36:40])[0]
        # Offset 40-41: Extended flags
        extended_flags = struct.unpack('<H', self.data[40:42])[0]
        # Offset 42-43: FAT32 version
        fat32_version = struct.unpack('<H', self.data[42:44])[0]
        # Offset 44-47: Root directory cluster
        root_dir_cluster = struct.unpack('<I', self.data[44:48])[0]
        # Offset 48-49: FSInfo sector
        fsinfo_sector = struct.unpack('<H', self.data[48:50])[0]
        # Offset 50-51: Backup boot sector
        backup_boot_sector = struct.unpack('<H', self.data[50:52])[0]
        # Offset 52-63: Reserved
        # Offset 64: Drive number
        drive_number = self.data[64]
        # Offset 65: Reserved
        # Offset 66: Boot signature
        boot_signature = self.data[66]
        # Offset 67-70: Volume ID
        volume_id = struct.unpack('<I', self.data[67:71])[0]
        # Offset 71-81: Volume label
        volume_label = self.data[71:82].decode('ascii', errors='ignore').strip()
        # Offset 82-89: File system type
        filesystem_type = self.data[82:90].decode('ascii', errors='ignore').strip()
        
        report.append("📋 BPB (BIOS Parameter Block) Information:")
        report.append("-" * 80)
        report.append(f"OEM Name: {oem_name}")
        report.append(f"Bytes per Sector: {bytes_per_sector}")
        report.append(f"Sectors per Cluster: {sectors_per_cluster}")
        report.append(f"Cluster Size: {sectors_per_cluster * bytes_per_sector} bytes ({sectors_per_cluster * bytes_per_sector / 1024:.2f} KB)")
        report.append(f"Reserved Sectors: {reserved_sectors}")
        report.append(f"Number of FATs: {num_fats}")
        report.append(f"Root Directory Entries: {root_dir_entries} (0 = FAT32)")
        report.append(f"Total Sectors (32-bit): {total_sectors_32}")
        report.append(f"Sectors per FAT: {sectors_per_fat_32}")
        report.append(f"FAT Size: {sectors_per_fat_32 * bytes_per_sector:,} bytes ({sectors_per_fat_32 * bytes_per_sector / (1024*1024):.2f} MB)")
        report.append(f"Root Directory Cluster: {root_dir_cluster}")
        report.append(f"FSInfo Sector: {fsinfo_sector}")
        report.append(f"Backup Boot Sector: {backup_boot_sector}")
        report.append(f"Volume ID: 0x{volume_id:08X}")
        report.append(f"Volume Label: {volume_label}")
        report.append(f"File System Type: {filesystem_type}")
        report.append("")
        
        # Calculate FAT locations
        fat1_start = reserved_sectors * bytes_per_sector
        fat2_start = fat1_start + (sectors_per_fat_32 * bytes_per_sector)
        data_area_start = fat2_start + (sectors_per_fat_32 * bytes_per_sector)
        
        report.append("📍 Filesystem Layout:")
        report.append("-" * 80)
        report.append(f"FAT1 Start: Sector {reserved_sectors} (offset {fat1_start:,} bytes)")
        report.append(f"FAT2 Start: Sector {reserved_sectors + sectors_per_fat_32} (offset {fat2_start:,} bytes)")
        report.append(f"Data Area Start: Sector {reserved_sectors + (sectors_per_fat_32 * 2)} (offset {data_area_start:,} bytes)")
        report.append("")
        
        # Analyze FAT for deleted files
        report.append("🔍 FAT Analysis (Deleted Files Detection):")
        report.append("-" * 80)
        
        deleted_files = []
        if fat1_start < len(self.data) and fat1_start + (sectors_per_fat_32 * bytes_per_sector) <= len(self.data):
            fat_data = self.data[fat1_start:fat1_start + (sectors_per_fat_32 * bytes_per_sector)]
            
            # Scan for deleted file entries (0xE5 in first byte of directory entry)
            # Root directory is at root_dir_cluster, but we'll scan from data area
            if data_area_start < len(self.data):
                # Scan first few clusters for directory entries
                scan_size = min(32 * sectors_per_cluster * bytes_per_sector, len(self.data) - data_area_start)
                data_scan = self.data[data_area_start:data_area_start + scan_size]
                
                # Directory entry is 32 bytes
                for i in range(0, len(data_scan) - 32, 32):
                    entry = data_scan[i:i+32]
                    # Check if first byte is 0xE5 (deleted) or 0x00 (unused)
                    if entry[0] == 0xE5:
                        # Parse directory entry
                        filename = entry[0:11].decode('ascii', errors='ignore')
                        attributes = entry[11]
                        # Skip volume label and long filename entries
                        if attributes != 0x08 and attributes != 0x0F:
                            cluster_high = struct.unpack('<H', entry[20:22])[0]
                            cluster_low = struct.unpack('<H', entry[26:28])[0]
                            cluster_num = (cluster_high << 16) | cluster_low
                            file_size = struct.unpack('<I', entry[28:32])[0]
                            
                            deleted_files.append({
                                'filename': filename,
                                'cluster': cluster_num,
                                'size': file_size
                            })
                    
                    if entry[0] == 0x00:
                        break  # End of directory
        
        if deleted_files:
            report.append(f"🗑️  Found {len(deleted_files)} deleted file entries:")
            for i, df in enumerate(deleted_files[:20]):  # Show first 20
                report.append(f"  {i+1}. {df['filename']} (Cluster: {df['cluster']}, Size: {df['size']:,} bytes)")
            if len(deleted_files) > 20:
                report.append(f"  ... and {len(deleted_files) - 20} more")
        else:
            report.append("✅ No deleted file entries found in scanned area")
        
        report.append("")
        
        # Anomaly detection
        report.append("🔍 Anomaly Detection:")
        report.append("-" * 80)
        
        anomalies = []
        
        # Check for invalid cluster size
        if sectors_per_cluster == 0:
            anomalies.append("⚠️  Invalid sectors per cluster (0)")
        
        # Check for invalid bytes per sector (must be power of 2, typically 512)
        if bytes_per_sector not in [512, 1024, 2048, 4096]:
            anomalies.append(f"⚠️  Unusual bytes per sector: {bytes_per_sector}")
        
        # Check boot signature
        if boot_signature != 0x29:
            anomalies.append(f"⚠️  Invalid boot signature: 0x{boot_signature:02X} (expected 0x29)")
        
        # Check for slack space (unused space in clusters)
        cluster_size = sectors_per_cluster * bytes_per_sector
        if cluster_size > 0:
            report.append(f"📊 Cluster Size: {cluster_size} bytes - potential slack space per cluster")
        
        if anomalies:
            for anomaly in anomalies:
                report.append(anomaly)
        else:
            report.append("✅ No obvious anomalies detected")
        
        report.append("")
        
        # إجابات الأسئلة العملية
        report.append(self.answer_fat32_questions(
            bytes_per_sector, sectors_per_cluster, reserved_sectors,
            num_fats, sectors_per_fat_32, root_dir_cluster,
            volume_id, volume_label, filesystem_type,
            deleted_files, fat1_start, fat2_start, data_area_start
        ))
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def answer_fat32_questions(self, bytes_per_sector, sectors_per_cluster, reserved_sectors,
                              num_fats, sectors_per_fat_32, root_dir_cluster,
                              volume_id, volume_label, filesystem_type,
                              deleted_files, fat1_start, fat2_start, data_area_start):
        """إجابة على أسئلة الاختبار العملي لـ FAT32"""
        answers = []
        answers.append("=" * 80)
        answers.append("📝 إجابات الأسئلة العملية - FAT32 (Practical Exam Answers)")
        answers.append("=" * 80)
        answers.append("")
        
        # سؤال: Bytes per Sector
        answers.append(f"📏 Bytes per Sector: {bytes_per_sector}")
        
        # سؤال: Sectors per Cluster
        answers.append(f"📦 Sectors per Cluster: {sectors_per_cluster}")
        
        # سؤال: Cluster Size
        cluster_size = sectors_per_cluster * bytes_per_sector
        answers.append(f"📊 Cluster Size: {cluster_size} bytes ({cluster_size/1024:.2f} KB)")
        
        # سؤال: Reserved Sectors
        answers.append(f"🔒 Reserved Sectors: {reserved_sectors}")
        
        # سؤال: Number of FATs
        answers.append(f"📋 Number of FATs: {num_fats}")
        
        # سؤال: Sectors per FAT
        answers.append(f"📏 Sectors per FAT: {sectors_per_fat_32}")
        
        # سؤال: FAT Size in bytes
        fat_size_bytes = sectors_per_fat_32 * bytes_per_sector
        answers.append(f"💾 FAT Size: {fat_size_bytes:,} bytes ({fat_size_bytes/(1024*1024):.2f} MB)")
        
        # سؤال: Root Directory Cluster
        answers.append(f"📁 Root Directory Cluster: {root_dir_cluster}")
        
        # سؤال: Volume ID
        answers.append(f"🆔 Volume ID: 0x{volume_id:08X}")
        
        # سؤال: Volume Label
        answers.append(f"🏷️  Volume Label: {volume_label}")
        
        # سؤال: File System Type
        answers.append(f"📂 File System Type: {filesystem_type}")
        
        # سؤال: FAT1/FAT2/Data Area locations
        answers.append("")
        answers.append("📍 Filesystem Layout:")
        answers.append(f"   FAT1 Start: Sector {reserved_sectors} (offset {fat1_start:,} bytes)")
        answers.append(f"   FAT2 Start: Sector {reserved_sectors + sectors_per_fat_32} (offset {fat2_start:,} bytes)")
        answers.append(f"   Data Area Start: Sector {reserved_sectors + (sectors_per_fat_32 * 2)} (offset {data_area_start:,} bytes)")
        
        # سؤال: Deleted Files
        answers.append("")
        answers.append(f"🗑️  عدد الملفات المحذوفة: {len(deleted_files)}")
        if deleted_files:
            answers.append("   قائمة الملفات المحذوفة:")
            for i, df in enumerate(deleted_files[:10], 1):
                answers.append(f"   {i}. {df['filename']} (Cluster: {df['cluster']}, Size: {df['size']:,} bytes)")
            if len(deleted_files) > 10:
                answers.append(f"   ... و {len(deleted_files) - 10} ملفات أخرى")
        
        return "\n".join(answers)
    
    def deep_fat_analysis(self):
        """تحليل FAT متقدم - Parse FAT Table, Detect Fragmentation, Extract Root Directory, Orphaned Clusters"""
        if len(self.data) < 512:
            return None
        
        report = []
        report.append("=" * 80)
        report.append("🔍 Deep FAT Structure Analysis")
        report.append("=" * 80)
        report.append("")
        
        try:
            # Parse BPB
            bytes_per_sector = struct.unpack('<H', self.data[11:13])[0]
            sectors_per_cluster = self.data[13]
            reserved_sectors = struct.unpack('<H', self.data[14:16])[0]
            num_fats = self.data[16]
            sectors_per_fat_32 = struct.unpack('<I', self.data[36:40])[0]
            root_dir_cluster = struct.unpack('<I', self.data[44:48])[0]
            
            # Calculate locations
            fat1_start = reserved_sectors * bytes_per_sector
            fat1_size = sectors_per_fat_32 * bytes_per_sector
            data_area_start = fat1_start + (sectors_per_fat_32 * num_fats * bytes_per_sector)
            cluster_size = sectors_per_cluster * bytes_per_sector
            
            if fat1_start + fat1_size > len(self.data):
                report.append("⚠️  FAT table extends beyond file size")
                return "\n".join(report)
            
            # Read FAT1
            fat_data = self.read_at_offset(fat1_start, min(fat1_size, len(self.data) - fat1_start))
            
            if len(fat_data) < 4:
                report.append("⚠️  FAT table too small")
                return "\n".join(report)
            
            report.append("📊 FAT Table Analysis:")
            report.append("-" * 80)
            
            # Parse FAT entries
            free_clusters = 0
            bad_clusters = 0
            allocated_clusters = 0
            cluster_chains = {}
            
            max_clusters = min(len(fat_data) // 4, 100000)
            
            for i in range(2, max_clusters):
                offset = i * 4
                if offset + 4 > len(fat_data):
                    break
                
                fat_entry = struct.unpack('<I', fat_data[offset:offset+4])[0] & 0x0FFFFFFF
                
                if fat_entry == 0x00000000:
                    free_clusters += 1
                elif fat_entry == 0x0FFFFFF7:
                    bad_clusters += 1
                elif fat_entry >= 0x0FFFFFF8:
                    allocated_clusters += 1
                elif fat_entry >= 0x00000002:
                    allocated_clusters += 1
                    if i not in cluster_chains:
                        cluster_chains[i] = []
                    cluster_chains[i].append(fat_entry)
            
            report.append(f"Total Clusters Analyzed: {max_clusters - 2}")
            report.append(f"Free Clusters: {free_clusters}")
            report.append(f"Allocated Clusters: {allocated_clusters}")
            report.append(f"Bad Clusters: {bad_clusters}")
            report.append(f"Cluster Chains Found: {len(cluster_chains)}")
            report.append("")
            
            # Fragmentation Detection
            report.append("🔍 Fragmentation Analysis:")
            report.append("-" * 80)
            fragmented_files = 0
            total_chains = len(cluster_chains)
            
            for start_cluster, chain in cluster_chains.items():
                if len(chain) > 1:
                    is_sequential = True
                    current = start_cluster
                    for next_cluster in chain:
                        if next_cluster != current + 1:
                            is_sequential = False
                            break
                        current = next_cluster
                    if not is_sequential:
                        fragmented_files += 1
            
            if total_chains > 0:
                fragmentation_ratio = (fragmented_files / total_chains) * 100
                report.append(f"Fragmented Files: {fragmented_files} / {total_chains} ({fragmentation_ratio:.1f}%)")
            report.append("")
            
            # Root Directory Extraction
            report.append("📁 Root Directory Contents:")
            report.append("-" * 80)
            
            if root_dir_cluster >= 2:
                root_dir_offset = data_area_start + ((root_dir_cluster - 2) * cluster_size)
                if root_dir_offset < len(self.data):
                    root_dir_data = self.read_at_offset(root_dir_offset, min(cluster_size, len(self.data) - root_dir_offset))
                    
                    files_found = []
                    for i in range(0, len(root_dir_data) - 32, 32):
                        entry = root_dir_data[i:i+32]
                        if entry[0] == 0x00:
                            break
                        if entry[0] == 0xE5 or entry[11] == 0x0F:
                            continue
                        
                        filename = entry[0:11].decode('ascii', errors='ignore').strip()
                        attributes = entry[11]
                        cluster_high = struct.unpack('<H', entry[20:22])[0]
                        cluster_low = struct.unpack('<H', entry[26:28])[0]
                        start_cluster = (cluster_high << 16) | cluster_low
                        file_size = struct.unpack('<I', entry[28:32])[0]
                        
                        file_type = "File"
                        if attributes & 0x10:
                            file_type = "Directory"
                        if attributes & 0x08:
                            file_type = "Volume Label"
                        
                        files_found.append({
                            'name': filename,
                            'type': file_type,
                            'cluster': start_cluster,
                            'size': file_size
                        })
                    
                    if files_found:
                        report.append(f"Found {len(files_found)} entries:")
                        for f in files_found[:20]:
                            report.append(f"  • {f['name']} ({f['type']}) - Cluster: {f['cluster']}, Size: {f['size']:,} bytes")
                        if len(files_found) > 20:
                            report.append(f"  ... and {len(files_found) - 20} more")
            
            report.append("")
            report.append("=" * 80)
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Error in deep FAT analysis: {str(e)}"
    
    def analyze_registry(self):
        """تحليل Registry Hive - هنا بنستخرج المفاتيح والقيم المهمة"""
        report = []
        report.append("=" * 80)
        report.append("تحليل Windows Registry Hive")
        report.append("=" * 80)
        report.append("")
        
        if len(self.data) < 4096:
            report.append("❌ الملف صغير جداً - Registry hive لازم يكون على الأقل 4KB")
            return "\n".join(report)
        
        # Parse Registry Header (first 4096 bytes)
        # Offset 0-3: Signature "regf"
        signature = self.data[0:4]
        if signature != b'regf':
            report.append("❌ Invalid registry signature")
            return "\n".join(report)
        
        # Offset 4-7: Primary sequence number
        primary_seq = struct.unpack('<I', self.data[4:8])[0]
        # Offset 8-11: Secondary sequence number
        secondary_seq = struct.unpack('<I', self.data[8:12])[0]
        # Offset 12-15: Last modification timestamp (FILETIME)
        last_modified = struct.unpack('<Q', self.data[12:20])[0]
        # Offset 20-23: Major version
        major_version = struct.unpack('<I', self.data[20:24])[0]
        # Offset 24-27: Minor version
        minor_version = struct.unpack('<I', self.data[24:28])[0]
        # Offset 28-31: File type
        file_type = struct.unpack('<I', self.data[28:32])[0]
        # Offset 32-35: Format version
        format_version = struct.unpack('<I', self.data[32:36])[0]
        # Offset 36-39: Root key offset
        root_key_offset = struct.unpack('<I', self.data[36:40])[0]
        # Offset 40-43: Hive bins data size
        hive_bins_size = struct.unpack('<I', self.data[40:44])[0]
        # Offset 44-47: Clustering factor
        clustering_factor = struct.unpack('<I', self.data[44:48])[0]
        # Offset 48-51: File name (UTF-16LE, 32 bytes = 16 chars)
        filename_bytes = self.data[48:80]
        try:
            hive_filename = filename_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
        except:
            hive_filename = "<Invalid>"
        
        # Convert FILETIME to readable date
        # FILETIME is 100-nanosecond intervals since 1601-01-01
        if last_modified > 0:
            filetime_epoch = datetime(1601, 1, 1)
            seconds = last_modified / 10000000.0
            last_modified_dt = filetime_epoch + timedelta(seconds=seconds)
            last_modified_str = last_modified_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            last_modified_str = "Not set"
        
        report.append("📋 Registry Hive Header:")
        report.append("-" * 80)
        report.append(f"Signature: {signature.decode('ascii', errors='ignore')}")
        report.append(f"Primary Sequence: {primary_seq}")
        report.append(f"Secondary Sequence: {secondary_seq}")
        report.append(f"Last Modified: {last_modified_str}")
        report.append(f"Version: {major_version}.{minor_version}")
        report.append(f"File Type: {file_type}")
        report.append(f"Format Version: {format_version}")
        report.append(f"Root Key Offset: 0x{root_key_offset:08X}")
        report.append(f"Hive Bins Size: {hive_bins_size:,} bytes")
        report.append(f"Clustering Factor: {clustering_factor}")
        report.append(f"Hive Filename: {hive_filename}")
        report.append("")
        
        # Detect hive type based on filename
        hive_type = "Unknown"
        if "SYSTEM" in hive_filename.upper():
            hive_type = "SYSTEM"
        elif "SOFTWARE" in hive_filename.upper():
            hive_type = "SOFTWARE"
        elif "SAM" in hive_filename.upper():
            hive_type = "SAM"
        elif "NTUSER.DAT" in hive_filename.upper() or "NTUSER" in hive_filename.upper():
            hive_type = "NTUSER.DAT"
        
        report.append(f"🔍 Detected Hive Type: {hive_type}")
        report.append("")
        
        # Parse root key and major keys
        report.append("🔑 Major Keys Detection:")
        report.append("-" * 80)
        
        # Search for common registry paths
        major_keys = []
        
        # Convert common paths to UTF-16LE for searching
        search_patterns = {
            "SOFTWARE": b'S\x00O\x00F\x00T\x00W\x00A\x00R\x00E\x00',
            "SYSTEM": b'S\x00Y\x00S\x00T\x00E\x00M\x00',
            "SAM": b'S\x00A\x00M\x00',
            "SECURITY": b'S\x00E\x00C\x00U\x00R\x00I\x00T\x00Y\x00',
            "Microsoft": b'M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00',
            "Windows": b'W\x00i\x00n\x00d\x00o\x00w\x00s\x00',
            "Run": b'R\x00u\x00n\x00',
            "RunOnce": b'R\x00u\x00n\x00O\x00n\x00c\x00e\x00'
        }
        
        for key_name, pattern in search_patterns.items():
            if pattern in self.data:
                major_keys.append(key_name)
                report.append(f"✅ Found: {key_name}")
        
        if not major_keys:
            report.append("⚠️  No major keys detected (may require deeper parsing)")
        
        report.append("")
        
        # Hive-specific analysis
        if hive_type == "SAM":
            report.append("👤 SAM Hive Analysis (User Accounts):")
            report.append("-" * 80)
            report.append("⚠️  Full SAM parsing requires complex binary structure analysis")
            report.append("   User account information is encrypted in SAM hive")
            report.append("   Recommendation: Use specialized tools (regedit, Registry Explorer)")
            report.append("")
        
        if hive_type == "SYSTEM" or hive_type == "SOFTWARE":
            report.append("🔍 System/Software Hive Analysis:")
            report.append("-" * 80)
            report.append("⚠️  Full registry parsing requires recursive key/value enumeration")
            report.append("   This tool provides header and signature detection")
            report.append("   For detailed analysis, use: regedit, Registry Explorer, or regripper")
            report.append("")
        
        if hive_type == "NTUSER.DAT":
            report.append("👤 NTUSER.DAT Analysis (User Profile):")
            report.append("-" * 80)
            report.append("⚠️  User profile hives contain:")
            report.append("   - User preferences and settings")
            report.append("   - Run keys (malware persistence)")
            report.append("   - USB device history")
            report.append("   - Browser history and bookmarks")
            report.append("   Full parsing requires specialized registry tools")
            report.append("")
        
        # Search for suspicious patterns
        report.append("🔍 Suspicious Patterns Detection:")
        report.append("-" * 80)
        
        suspicious_patterns = []
        
        # Search for common malware persistence locations (as UTF-16LE)
        malware_patterns = {
            "Run Key": b'R\x00u\x00n\x00',
            "RunOnce": b'R\x00u\x00n\x00O\x00n\x00c\x00e\x00',
            "Services": b'S\x00e\x00r\x00v\x00i\x00c\x00e\x00s\x00',
            "Startup": b'S\x00t\x00a\x00r\x00t\x00u\x00p\x00'
        }
        
        for pattern_name, pattern in malware_patterns.items():
            if pattern in self.data:
                suspicious_patterns.append(f"⚠️  Found potential {pattern_name} entry (malware persistence location)")
        
        # Search for executable extensions
        exe_patterns = [b'.exe\x00', b'.bat\x00', b'.cmd\x00', b'.vbs\x00', b'.ps1\x00']
        exe_found = False
        for pattern in exe_patterns:
            if pattern in self.data:
                exe_found = True
                break
        
        if exe_found:
            suspicious_patterns.append("⚠️  Found executable file references (potential malware)")
        
        if suspicious_patterns:
            for pattern in suspicious_patterns:
                report.append(pattern)
        else:
            report.append("✅ No obvious suspicious patterns detected")
        
        report.append("")
        
        # Check for modifications
        report.append("🔍 Modification Indicators:")
        report.append("-" * 80)
        
        # Check sequence numbers (should match if not modified)
        if primary_seq != secondary_seq:
            report.append(f"⚠️  Sequence numbers mismatch (Primary: {primary_seq}, Secondary: {secondary_seq})")
            report.append("   This may indicate hive modification or corruption")
        else:
            report.append(f"✅ Sequence numbers match: {primary_seq}")
        
        report.append("")
        
        # إجابات الأسئلة العملية
        report.append(self.answer_registry_questions(hive_type, self.data))
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def answer_registry_questions(self, hive_type, data):
        """إجابة على أسئلة الاختبار العملي لـ Registry"""
        answers = []
        answers.append("=" * 80)
        answers.append("📝 إجابات الأسئلة العملية - Registry (Practical Exam Answers)")
        answers.append("=" * 80)
        answers.append("")
        
        # البحث عن UserAssist (NTUSER.DAT)
        if hive_type == "NTUSER.DAT":
            userassist_info = self.search_userassist(data)
            if userassist_info:
                answers.append("👤 UserAssist Information:")
                answers.append("-" * 80)
                for app, count in userassist_info.items():
                    answers.append(f"   {app}: تم تشغيله {count} مرة/مرات")
                answers.append("")
            
            # البحث عن Recent Docs
            recent_docs = self.search_recent_docs(data)
            if recent_docs:
                answers.append("📄 Recent Documents:")
                answers.append("-" * 80)
                for i, doc in enumerate(recent_docs[:10], 1):
                    answers.append(f"   {i}. {doc}")
                if len(recent_docs) > 10:
                    answers.append(f"   ... و {len(recent_docs) - 10} ملفات أخرى")
                answers.append("")
        
        # البحث عن USB Devices (SYSTEM hive)
        if hive_type == "SYSTEM":
            usb_devices = self.search_usb_devices(data)
            if usb_devices:
                answers.append("🔌 USB Devices:")
                answers.append("-" * 80)
                for device in usb_devices:
                    answers.append(f"   Vendor: {device.get('vendor', 'Unknown')}")
                    answers.append(f"   Product: {device.get('product', 'Unknown')}")
                    if 'serial' in device:
                        answers.append(f"   Serial Number: {device['serial']}")
                    if 'friendly_name' in device:
                        answers.append(f"   Friendly Name: {device['friendly_name']}")
                    if 'volume_name' in device:
                        answers.append(f"   Volume Name: {device['volume_name']}")
                    answers.append("")
        
        # البحث عن ShimCache/AppCompatCache (SYSTEM hive)
        if hive_type == "SYSTEM":
            shimcache_info = self.search_shimcache(data)
            if shimcache_info:
                answers.append("💾 ShimCache/AppCompatCache:")
                answers.append("-" * 80)
                answers.append(f"   عدد البرامج المسجلة: {len(shimcache_info)}")
                for i, app in enumerate(shimcache_info[:5], 1):
                    answers.append(f"   {i}. {app}")
                if len(shimcache_info) > 5:
                    answers.append(f"   ... و {len(shimcache_info) - 5} برامج أخرى")
                answers.append("")
        
        # البحث عن BAM/DAM (SYSTEM hive)
        if hive_type == "SYSTEM":
            bam_dam_info = self.search_bam_dam(data)
            if bam_dam_info:
                answers.append("⚡ BAM/DAM Information:")
                answers.append("-" * 80)
                for program, info in bam_dam_info.items():
                    answers.append(f"   {program}: {info}")
                answers.append("")
        
        if len(answers) == 3:  # Only header and separator
            answers.append("⚠️  لم يتم العثور على معلومات إضافية للإجابة على الأسئلة")
            answers.append("   (قد يتطلب تحليل أعمق باستخدام أدوات متخصصة)")
        
        return "\n".join(answers)
    
    def search_userassist(self, data):
        """البحث عن معلومات UserAssist"""
        userassist = {}
        # البحث عن أنماط UserAssist (UTF-16LE و ASCII)
        patterns = {
            (b'E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00', b'Explorer'): 'File Explorer',
            (b'N\x00o\x00t\x00e\x00p\x00a\x00d\x00', b'Notepad'): 'Notepad',
            (b'C\x00a\x00l\x00c\x00', b'Calc'): 'Calculator',
            (b'W\x00o\x00r\x00d\x00', b'Word'): 'Word',
            (b'E\x00x\x00c\x00e\x00l\x00', b'Excel'): 'Excel',
            (b'P\x00o\x00w\x00e\x00r\x00S\x00h\x00e\x00l\x00l\x00', b'PowerShell'): 'PowerShell'
        }
        
        for (utf16_pattern, ascii_pattern), name in patterns.items():
            count_utf16 = data.count(utf16_pattern)
            count_ascii = data.count(ascii_pattern)
            total_count = count_utf16 + count_ascii
            if total_count > 0:
                # تقدير عدد مرات التشغيل بناءً على التكرار
                estimated_runs = max(1, total_count // 3)
                userassist[name] = estimated_runs
        
        return userassist if userassist else None
    
    def search_recent_docs(self, data):
        """البحث عن Recent Documents"""
        recent_docs = []
        # البحث عن أنماط الملفات الشائعة في Recent Docs
        # هذا بحث بسيط - التحليل الكامل يتطلب parsing معقد
        
        # البحث عن مسارات ملفات
        doc_patterns = [
            b'.pdf\x00', b'.docx\x00', b'.doc\x00',
            b'.xlsx\x00', b'.txt\x00', b'.jpg\x00'
        ]
        
        for pattern in doc_patterns:
            idx = data.find(pattern)
            if idx != -1:
                # محاولة استخراج اسم الملف من السياق
                start = max(0, idx - 50)
                end = min(len(data), idx + 20)
                context = data[start:end]
                try:
                    # البحث عن أسماء ملفات قابلة للقراءة
                    decoded = context.decode('utf-16-le', errors='ignore')
                    if any(c.isalnum() for c in decoded):
                        recent_docs.append(f"File with {pattern.decode('ascii', errors='ignore')} extension found")
                except:
                    pass
        
        return recent_docs[:20] if recent_docs else None
    
    def search_usb_devices(self, data):
        """البحث عن معلومات USB Devices"""
        usb_devices = []
        
        # البحث عن Vendor IDs شائعة (ASCII و UTF-16LE)
        vendors = {
            'Kingston': [b'Kingston', b'K\x00i\x00n\x00g\x00s\x00t\x00o\x00n\x00'],
            'SanDisk': [b'SanDisk', b'S\x00a\x00n\x00D\x00i\x00s\x00k\x00'],
            'Samsung': [b'Samsung', b'S\x00a\x00m\x00s\x00u\x00n\x00g\x00'],
            'Seagate': [b'Seagate', b'S\x00e\x00a\x00g\x00a\x00t\x00e\x00']
        }
        
        for vendor_name, patterns in vendors.items():
            found = False
            for pattern in patterns:
                if pattern in data:
                    found = True
                    vendor_idx = data.find(pattern)
                    device = {'vendor': vendor_name}
                    
                    # محاولة العثور على معلومات إضافية في المنطقة المحيطة
                    start = max(0, vendor_idx - 200)
                    end = min(len(data), vendor_idx + 1000)
                    search_area = data[start:end]
                    
                    # البحث عن Serial Number patterns (عادة أرقام/حروف/شرطات)
                    # البحث عن Volume Name
                    volume_patterns = [b'USBSTOR', b'Disk&Ven', b'Ven_', b'Prod_']
                    for vol_pattern in volume_patterns:
                        if vol_pattern in search_area:
                            device['volume_name'] = vol_pattern.decode('ascii', errors='ignore')
                            break
                    
                    # البحث عن Friendly Name
                    if b'FriendlyName' in search_area or b'friendly' in search_area.lower():
                        device['friendly_name'] = f"{vendor_name} USB Device"
                    
                    # محاولة استخراج Serial (هذا يتطلب parsing معقد أكثر)
                    # للاختبار العملي، نبحث عن أنماط Serial Number
                    serial_patterns = [b'Serial', b'SERIAL', b'SN']
                    for serial_pat in serial_patterns:
                        if serial_pat in search_area:
                            # محاولة استخراج القيمة بعد Serial
                            serial_idx = search_area.find(serial_pat)
                            if serial_idx != -1:
                                # البحث عن قيمة بعد Serial
                                value_start = serial_idx + len(serial_pat)
                                value_end = min(len(search_area), value_start + 50)
                                value_area = search_area[value_start:value_end]
                                # البحث عن أرقام/حروف
                                try:
                                    decoded = value_area.decode('ascii', errors='ignore')
                                    # استخراج أي أرقام/حروف متتالية
                                    matches = re.findall(r'[A-Z0-9]{4,}', decoded)
                                    if matches:
                                        device['serial'] = matches[0]
                                except:
                                    pass
                            break
                    
                    if vendor_name not in [d.get('vendor') for d in usb_devices]:
                        usb_devices.append(device)
                    break
        
        return usb_devices if usb_devices else None
    
    def search_shimcache(self, data):
        """البحث عن ShimCache entries"""
        shimcache = []
        
        # البحث عن أنماط مسارات البرامج الشائعة
        program_patterns = [
            b'C:\\Windows\\',
            b'C:\\Program Files\\',
            b'.exe\x00',
            b'AppCompatCache'
        ]
        
        for pattern in program_patterns:
            if pattern in data:
                shimcache.append(f"Found {pattern.decode('ascii', errors='ignore')} reference")
        
        return shimcache[:10] if shimcache else None
    
    def search_bam_dam(self, data):
        """البحث عن BAM/DAM information"""
        bam_dam = {}
        
        # البحث عن أنماط BAM/DAM
        if b'BAM' in data or b'bam' in data:
            bam_dam['BAM'] = "Background Activity Monitor data found"
        
        if b'DAM' in data or b'dam' in data:
            bam_dam['DAM'] = "Desktop Activity Moderator data found"
        
        return bam_dam if bam_dam else None
    
    def generate_report(self, output_callback=None):
        """ديه الوظيفة الرئيسية - بتجمع كل التحليلات وتطلع التقرير النهائي"""
        # لو مفيش callback، نستخدم print العادي (للسطر الأوامر)
        if output_callback is None:
            # Create a safe print function that handles encoding errors
            def safe_print(text):
                try:
                    print(text)
                except UnicodeEncodeError:
                    # Fallback: encode to ASCII with replacement for emojis
                    safe_text = text.encode('ascii', errors='replace').decode('ascii')
                    print(safe_text)
            output_callback = safe_print
        
        if not self.read_file():
            output_callback("❌ فشل في قراءة الملف")
            return ""
        
        report_lines = []
        report_lines.append("\n" + "=" * 80)
        report_lines.append("🔍 Digital Forensics Analysis Tool")
        report_lines.append("=" * 80)
        report_lines.append(f"\n📁 File: {self.filepath}")
        report_lines.append(f"📏 Size: {self.file_size:,} bytes ({self.file_size / (1024*1024):.2f} MB)")
        report_lines.append("\n🔎 Detecting file type...")
        
        file_type = self.detect_file_type()
        
        if not file_type:
            report_lines.append("\n❌ Unknown file type - Could not detect MBR, GPT, FAT32, or Registry")
            report_lines.append("\n💡 Supported formats:")
            report_lines.append("   - MBR boot sector (signature 0x55AA)")
            report_lines.append("   - GPT partition table (EFI PART signature)")
            report_lines.append("   - FAT32 filesystem (FAT32 label)")
            report_lines.append("   - Windows Registry hive (regf signature)")
            full_report = "\n".join(report_lines)
            output_callback(full_report)
            return full_report
        
        report_lines.append(f"✅ Detected: {file_type}")
        report_lines.append("\n" + "=" * 80)
        report_lines.append("📊 FORENSIC ANALYSIS REPORT")
        report_lines.append("=" * 80 + "\n")
        
        # Run appropriate analysis
        if file_type == 'MBR':
            analysis_report = self.analyze_mbr()
        elif file_type == 'GPT':
            analysis_report = self.analyze_gpt()
        elif file_type == 'FAT32':
            analysis_report = self.analyze_fat32()
        elif file_type == 'REGISTRY':
            analysis_report = self.analyze_registry()
        else:
            analysis_report = "Unknown file type"
        
        report_lines.append(analysis_report)
        
        # Always run encryption analysis
        report_lines.append("\n")
        report_lines.append(self.analyze_encryption())
        
        report_lines.append("\n" + "=" * 80)
        report_lines.append("✅ Analysis Complete")
        report_lines.append("=" * 80 + "\n")
        
        full_report = "\n".join(report_lines)
        output_callback(full_report)
        return full_report


class ForensicGUI:
    """واجهة رسومية للأداة - هنا بنعمل النوافذ والأزرار"""
    
    def __init__(self):
        """نبدأ بإنشاء النافذة الرئيسية"""
        self.root = tk.Tk()
        self.root.title("أداة تحليل الأدلة الرقمية - Digital Forensics Analyzer")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        # المتغيرات
        self.selected_file = tk.StringVar()
        self.selected_file.set("لم يتم اختيار ملف")
        self.analyzer = None
        self.analysis_results = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """ديه بنبني الواجهة - الأزرار والحقول مع Tabs"""
        
        # عنوان رئيسي
        title_frame = tk.Frame(self.root, bg="#2196F3", pady=10)
        title_frame.pack(fill=tk.X)
        
        title_label = tk.Label(
            title_frame,
            text="🔍 أداة تحليل الأدلة الرقمية - Digital Forensics Analyzer",
            font=("Arial", 16, "bold"),
            bg="#2196F3",
            fg="white"
        )
        title_label.pack()
        
        # إطار لاختيار الملف
        file_frame = tk.Frame(self.root, pady=10)
        file_frame.pack(fill=tk.X, padx=20)
        
        # حقل لعرض المسار المختار
        file_label = tk.Label(
            file_frame,
            text="الملف المختار:",
            font=("Arial", 10, "bold")
        )
        file_label.pack(anchor=tk.W)
        
        # حقل نصي لعرض المسار
        file_entry = tk.Entry(
            file_frame,
            textvariable=self.selected_file,
            font=("Arial", 9),
            state="readonly",
            width=60
        )
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # زر تصفح الملفات
        browse_button = tk.Button(
            file_frame,
            text="📁 تصفح",
            command=self.browse_file,
            font=("Arial", 10, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=5,
            cursor="hand2"
        )
        browse_button.pack(side=tk.RIGHT)
        
        # زر تحليل
        analyze_button = tk.Button(
            self.root,
            text="🔍 بدء التحليل",
            command=self.analyze_file,
            font=("Arial", 12, "bold"),
            bg="#2196F3",
            fg="white",
            padx=30,
            pady=10,
            cursor="hand2"
        )
        analyze_button.pack(pady=10)
        
        # إنشاء Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Tab 1: MBR Analysis
        self.tab_mbr = tk.Frame(self.notebook)
        self.notebook.add(self.tab_mbr, text="📋 MBR Analysis")
        self.setup_mbr_tab()
        
        # Tab 2: GPT Analysis
        self.tab_gpt = tk.Frame(self.notebook)
        self.notebook.add(self.tab_gpt, text="📋 GPT Analysis")
        self.setup_gpt_tab()
        
        # Tab 3: FAT/NTFS/EXT Details
        self.tab_filesystem = tk.Frame(self.notebook)
        self.notebook.add(self.tab_filesystem, text="💾 Filesystem Details")
        self.setup_filesystem_tab()
        
        # Tab 4: Registry Analysis
        self.tab_registry = tk.Frame(self.notebook)
        self.notebook.add(self.tab_registry, text="🔑 Registry Analysis")
        self.setup_registry_tab()
        
        # Tab 5: Encryption Analysis
        self.tab_encryption = tk.Frame(self.notebook)
        self.notebook.add(self.tab_encryption, text="🔐 Encryption")
        self.setup_encryption_tab()
        
        # Tab 6: Anomaly Report
        self.tab_anomalies = tk.Frame(self.notebook)
        self.notebook.add(self.tab_anomalies, text="⚠️  Anomaly Report")
        self.setup_anomalies_tab()
        
        # Tab 7: Hex View
        self.tab_hex = tk.Frame(self.notebook)
        self.notebook.add(self.tab_hex, text="🔢 Hex View")
        self.setup_hex_tab()
    
    def setup_mbr_tab(self):
        """إعداد تبويب MBR"""
        self.text_mbr = scrolledtext.ScrolledText(
            self.tab_mbr,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#f5f5f5"
        )
        self.text_mbr.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_gpt_tab(self):
        """إعداد تبويب GPT"""
        self.text_gpt = scrolledtext.ScrolledText(
            self.tab_gpt,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#f5f5f5"
        )
        self.text_gpt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_filesystem_tab(self):
        """إعداد تبويب Filesystem"""
        self.text_filesystem = scrolledtext.ScrolledText(
            self.tab_filesystem,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#f5f5f5"
        )
        self.text_filesystem.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_encryption_tab(self):
        """إعداد تبويب Encryption"""
        self.text_encryption = scrolledtext.ScrolledText(
            self.tab_encryption,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#f0f0f0"
        )
        self.text_encryption.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_registry_tab(self):
        """إعداد تبويب Registry"""
        self.text_registry = scrolledtext.ScrolledText(
            self.tab_registry,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#f5f5f5"
        )
        self.text_registry.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_anomalies_tab(self):
        """إعداد تبويب Anomalies"""
        self.text_anomalies = scrolledtext.ScrolledText(
            self.tab_anomalies,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#fff3cd"
        )
        self.text_anomalies.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_hex_tab(self):
        """إعداد تبويب Hex View احترافي مثل HxD"""
        # Initialize instance variables
        self.byte_grouping = 1
        self.selection_start = None
        self.selection_end = None
        self.current_offset = 0
        self.search_last_pos = 0
        
        # إطار للأدوات - Top Toolbar
        hex_toolbar = tk.Frame(self.tab_hex)
        hex_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # حقل Jump-to-Offset
        tk.Label(hex_toolbar, text="Jump to Offset:", font=("Arial", 9)).pack(side=tk.LEFT, padx=5)
        
        self.offset_entry = tk.Entry(hex_toolbar, width=20, font=("Courier", 9))
        self.offset_entry.pack(side=tk.LEFT, padx=5)
        self.offset_entry.insert(0, "0")
        
        # زر Jump
        jump_button = tk.Button(
            hex_toolbar,
            text="📍 Jump",
            command=self.jump_to_offset,
            font=("Arial", 9, "bold"),
            bg="#FF9800",
            fg="white",
            padx=10,
            cursor="hand2"
        )
        jump_button.pack(side=tk.LEFT, padx=5)
        
        # زر Jump from LBA
        tk.Label(hex_toolbar, text="Or LBA:", font=("Arial", 9)).pack(side=tk.LEFT, padx=5)
        self.lba_entry = tk.Entry(hex_toolbar, width=15, font=("Courier", 9))
        self.lba_entry.pack(side=tk.LEFT, padx=5)
        
        lba_jump_button = tk.Button(
            hex_toolbar,
            text="📍 Jump (LBA)",
            command=self.jump_from_lba,
            font=("Arial", 9, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=10,
            cursor="hand2"
        )
        lba_jump_button.pack(side=tk.LEFT, padx=5)
        
        # Byte Grouping
        tk.Label(hex_toolbar, text="Grouping:", font=("Arial", 9)).pack(side=tk.LEFT, padx=(20, 5))
        self.grouping_combo = ttk.Combobox(
            hex_toolbar,
            values=[1, 2, 4, 8],
            width=5,
            state="readonly",
            font=("Arial", 9)
        )
        self.grouping_combo.set(1)
        self.grouping_combo.pack(side=tk.LEFT, padx=5)
        self.grouping_combo.bind("<<ComboboxSelected>>", self.change_byte_grouping)
        
        # Search Field
        tk.Label(hex_toolbar, text="Search:", font=("Arial", 9)).pack(side=tk.LEFT, padx=(20, 5))
        self.search_entry = tk.Entry(hex_toolbar, width=20, font=("Courier", 9))
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        # Search Button
        search_button = tk.Button(
            hex_toolbar,
            text="🔍 Find",
            command=self.search_hex,
            font=("Arial", 9, "bold"),
            bg="#2196F3",
            fg="white",
            padx=10,
            cursor="hand2"
        )
        search_button.pack(side=tk.LEFT, padx=5)
        
        # Copy Button
        copy_button = tk.Button(
            hex_toolbar,
            text="📋 Copy",
            command=self.copy_selection,
            font=("Arial", 9, "bold"),
            bg="#9C27B0",
            fg="white",
            padx=10,
            cursor="hand2"
        )
        copy_button.pack(side=tk.LEFT, padx=5)
        
        # Main container for hex view and data inspector
        main_container = tk.Frame(self.tab_hex)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side: Hex viewer
        hex_container = tk.Frame(main_container)
        hex_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Column Headers Frame
        headers_frame = tk.Frame(hex_container, bg="#2d2d30")
        headers_frame.pack(fill=tk.X)
        
        # Header for offset column
        offset_header = tk.Label(
            headers_frame,
            text="Offset",
            font=("Courier", 9, "bold"),
            bg="#2d2d30",
            fg="#ffffff",
            width=10,
            anchor="w"
        )
        offset_header.pack(side=tk.LEFT, padx=2)
        
        # Header for hex columns (00-0F)
        hex_header_text = "  " + "  ".join(f"{i:02X}" for i in range(16))
        hex_header = tk.Label(
            headers_frame,
            text=hex_header_text,
            font=("Courier", 9, "bold"),
            bg="#2d2d30",
            fg="#ffffff",
            anchor="w"
        )
        hex_header.pack(side=tk.LEFT, padx=2)
        
        # Header for ASCII column
        ascii_header = tk.Label(
            headers_frame,
            text="  ASCII",
            font=("Courier", 9, "bold"),
            bg="#2d2d30",
            fg="#ffffff",
            width=18,
            anchor="w"
        )
        ascii_header.pack(side=tk.LEFT, padx=2)
        
        # Three-panel layout for offset, hex, and ASCII
        viewer_frame = tk.Frame(hex_container)
        viewer_frame.pack(fill=tk.BOTH, expand=True)
        
        # Offset column (read-only)
        self.text_offset = tk.Text(
            viewer_frame,
            width=10,
            wrap=tk.NONE,
            font=("Courier", 9),
            bg="#1e1e1e",
            fg="#858585",
            state=tk.DISABLED,
            cursor="arrow"
        )
        self.text_offset.pack(side=tk.LEFT, fill=tk.Y)
        
        # Hex data column
        self.text_hex_data = tk.Text(
            viewer_frame,
            width=50,
            wrap=tk.NONE,
            font=("Courier", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white",
            cursor="xterm"
        )
        self.text_hex_data.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # ASCII column
        self.text_ascii = tk.Text(
            viewer_frame,
            width=18,
            wrap=tk.NONE,
            font=("Courier", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            cursor="xterm"
        )
        self.text_ascii.pack(side=tk.LEFT, fill=tk.Y)
        
        # Shared scrollbar
        scrollbar = tk.Scrollbar(viewer_frame, command=self.sync_scroll)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        
        # Configure scrollbar for all three text widgets
        self.text_offset.config(yscrollcommand=self.on_text_scroll)
        self.text_hex_data.config(yscrollcommand=self.on_text_scroll)
        self.text_ascii.config(yscrollcommand=self.on_text_scroll)
        
        # Store scrollbar reference
        self.hex_scrollbar = scrollbar
        
        # Configure tags for formatting
        self.text_hex_data.tag_config("selection", background="#0078D7", foreground="white")
        self.text_hex_data.tag_config("highlight_byte", background="#FFD700", foreground="black")
        self.text_hex_data.tag_config("null_byte", foreground="#808080")
        self.text_hex_data.tag_config("printable", foreground="#a8d4a8")
        
        self.text_ascii.tag_config("selection", background="#0078D7", foreground="white")
        self.text_ascii.tag_config("highlight_byte", background="#FFD700", foreground="black")
        self.text_ascii.tag_config("null_byte", foreground="#808080")
        self.text_ascii.tag_config("printable", foreground="#a8d4a8")
        
        # Mouse event bindings
        self.text_hex_data.bind("<Button-1>", self.on_hex_click)
        self.text_hex_data.bind("<B1-Motion>", self.on_hex_drag)
        self.text_ascii.bind("<Button-1>", self.on_ascii_click)
        self.text_ascii.bind("<B1-Motion>", self.on_ascii_drag)
        
        # Keyboard shortcuts
        self.text_hex_data.bind("<Control-f>", lambda e: self.search_entry.focus())
        self.text_hex_data.bind("<Control-c>", lambda e: self.copy_selection())
        self.text_hex_data.bind("<Control-g>", lambda e: self.offset_entry.focus())
        self.text_hex_data.bind("<F3>", lambda e: self.search_hex())
        
        # Right side: Data Inspector Panel
        inspector_frame = tk.LabelFrame(
            main_container,
            text="Data Inspector",
            font=("Arial", 10, "bold"),
            bg="#2d2d30",
            fg="#ffffff",
            padx=10,
            pady=10
        )
        inspector_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(5, 0))
        
        # Data Inspector Labels
        inspector_font = ("Courier", 9)
        self.inspector_labels = {}
        
        inspector_items = [
            ("Int8:", "int8"),
            ("UInt8:", "uint8"),
            ("Int16 LE:", "int16_le"),
            ("Int16 BE:", "int16_be"),
            ("Int32 LE:", "int32_le"),
            ("Int32 BE:", "int32_be"),
            ("Int64 LE:", "int64_le"),
            ("Int64 BE:", "int64_be"),
            ("Float:", "float"),
            ("Double:", "double"),
            ("Binary:", "binary"),
            ("Decimal:", "decimal"),
            ("Hex:", "hex")
        ]
        
        for label_text, key in inspector_items:
            frame = tk.Frame(inspector_frame, bg="#2d2d30")
            frame.pack(fill=tk.X, pady=2)
            
            tk.Label(
                frame,
                text=label_text,
                font=inspector_font,
                bg="#2d2d30",
                fg="#ffffff",
                width=12,
                anchor="w"
            ).pack(side=tk.LEFT)
            
            value_label = tk.Label(
                frame,
                text="--",
                font=inspector_font,
                bg="#1e1e1e",
                fg="#d4d4d4",
                width=20,
                anchor="w"
            )
            value_label.pack(side=tk.LEFT, padx=5)
            self.inspector_labels[key] = value_label
        
        # Status Bar at the bottom
        status_frame = tk.Frame(self.tab_hex, bg="#2d2d30", height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Status bar labels
        self.status_offset = tk.Label(
            status_frame,
            text="Offset: 0x00000000 (0)",
            font=("Courier", 9),
            bg="#2d2d30",
            fg="#ffffff",
            anchor="w"
        )
        self.status_offset.pack(side=tk.LEFT, padx=10)
        
        self.status_selection = tk.Label(
            status_frame,
            text="Selection: None",
            font=("Courier", 9),
            bg="#2d2d30",
            fg="#ffffff",
            anchor="w"
        )
        self.status_selection.pack(side=tk.LEFT, padx=10)
        
        self.status_size = tk.Label(
            status_frame,
            text="Size: 0 bytes",
            font=("Courier", 9),
            bg="#2d2d30",
            fg="#ffffff",
            anchor="w"
        )
        self.status_size.pack(side=tk.LEFT, padx=10)
        
        self.status_value = tk.Label(
            status_frame,
            text="Value: --",
            font=("Courier", 9),
            bg="#2d2d30",
            fg="#ffffff",
            anchor="w"
        )
        self.status_value.pack(side=tk.LEFT, padx=10)
        
        # Keep reference to old text_hex for compatibility
        self.text_hex = self.text_hex_data
    
    def jump_to_offset(self):
        """القفز إلى offset محدد"""
        try:
            offset_str = self.offset_entry.get().strip()
            if offset_str.startswith('0x') or offset_str.startswith('0X'):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)
            
            if self.analyzer and self.analyzer.data:
                if offset < len(self.analyzer.data):
                    self.current_offset = offset
                    self.display_hex_at_offset(offset)
                    self.update_status_bar()
                else:
                    messagebox.showwarning("تحذير", f"Offset {hex(offset)} خارج نطاق الملف")
            else:
                messagebox.showwarning("تحذير", "لم يتم تحليل ملف بعد")
        except ValueError:
            messagebox.showerror("خطأ", "قيمة offset غير صحيحة")
    
    def jump_from_lba(self):
        """القفز من LBA"""
        try:
            lba = int(self.lba_entry.get().strip())
            offset = lba * 512
            
            if self.analyzer and self.analyzer.data:
                if offset < len(self.analyzer.data):
                    self.current_offset = offset
                    self.display_hex_at_offset(offset)
                    self.update_status_bar()
                else:
                    messagebox.showwarning("تحذير", f"LBA {lba} (offset {hex(offset)}) خارج نطاق الملف")
            else:
                messagebox.showwarning("تحذير", "لم يتم تحليل ملف بعد")
        except ValueError:
            messagebox.showerror("خطأ", "قيمة LBA غير صحيحة")
    
    def display_hex_at_offset(self, offset, size=512):
        """عرض Hex من offset محدد بتنسيق احترافي"""
        if not self.analyzer or not self.analyzer.data:
            return
        
        self.current_offset = offset
        
        # Enable editing
        self.text_offset.config(state=tk.NORMAL)
        self.text_hex_data.config(state=tk.NORMAL)
        self.text_ascii.config(state=tk.NORMAL)
        
        # Clear previous content
        self.text_offset.delete(1.0, tk.END)
        self.text_hex_data.delete(1.0, tk.END)
        self.text_ascii.delete(1.0, tk.END)
        
        # Remove previous tags
        self.text_hex_data.tag_remove("highlight_byte", "1.0", tk.END)
        self.text_hex_data.tag_remove("selection", "1.0", tk.END)
        self.text_hex_data.tag_remove("null_byte", "1.0", tk.END)
        self.text_hex_data.tag_remove("printable", "1.0", tk.END)
        
        self.text_ascii.tag_remove("highlight_byte", "1.0", tk.END)
        self.text_ascii.tag_remove("selection", "1.0", tk.END)
        self.text_ascii.tag_remove("null_byte", "1.0", tk.END)
        self.text_ascii.tag_remove("printable", "1.0", tk.END)
        
        # Read data
        data = self.analyzer.read_at_offset(offset, min(size, len(self.analyzer.data) - offset))
        
        # Get byte grouping
        grouping = int(self.byte_grouping)
        bytes_per_line = 16
        
        # Layout constants: each byte is "XX " (3 chars), group separator is "  " (2 chars)
        # Within a group, each byte takes 3 chars ("XX "), but the last byte in group has no trailing space
        # So group_width = grouping * 3 - 1
        # Gap between groups = 2
        group_width = grouping * 3 - 1
        gap_width = 2
        
        # Display data line by line
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            line_offset = offset + i
            
            # Offset column
            self.text_offset.insert(tk.END, f"{line_offset:08X}\n")
            
            # Hex data column with grouping - build line explicitly
            hex_line = ""
            for group_idx in range(bytes_per_line // grouping):
                if group_idx > 0:
                    hex_line += "  "  # Gap between groups
                
                start_byte = group_idx * grouping
                end_byte = min(start_byte + grouping, len(chunk))
                
                for byte_in_group in range(grouping):
                    byte_idx = start_byte + byte_in_group
                    if byte_idx < len(chunk):
                        hex_line += f"{chunk[byte_idx]:02X}"
                    else:
                        hex_line += "  "  # Padding for missing bytes
                    
                    # Add space after byte except for last byte in group
                    if byte_in_group < grouping - 1:
                        hex_line += " "
            
            self.text_hex_data.insert(tk.END, hex_line + "\n")
            
            # ASCII column
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            # Pad ASCII if needed
            ascii_str = ascii_str.ljust(bytes_per_line)
            self.text_ascii.insert(tk.END, ascii_str + "\n")
            
            # Apply tags for null bytes and printable characters
            line_num = (i // bytes_per_line) + 1
            for j, byte in enumerate(chunk):
                # Calculate position in hex column using same constants
                group_idx = j // grouping
                byte_in_group = j % grouping
                
                # Position: sum of all previous groups (each group_width) + gaps + current byte position
                hex_pos = group_idx * (group_width + gap_width) + byte_in_group * 3
                
                hex_start = f"{line_num}.{hex_pos}"
                hex_end = f"{line_num}.{hex_pos + 2}"
                
                ascii_start = f"{line_num}.{j}"
                ascii_end = f"{line_num}.{j + 1}"
                
                if byte == 0:
                    self.text_hex_data.tag_add("null_byte", hex_start, hex_end)
                    self.text_ascii.tag_add("null_byte", ascii_start, ascii_end)
                elif 32 <= byte < 127:
                    self.text_hex_data.tag_add("printable", hex_start, hex_end)
                    self.text_ascii.tag_add("printable", ascii_start, ascii_end)
            
            # Highlight first byte in first line
            if i == 0 and len(chunk) > 0:
                self.text_hex_data.tag_add("highlight_byte", "1.0", "1.2")
                self.text_ascii.tag_add("highlight_byte", "1.0", "1.1")
        
        # Disable editing
        self.text_offset.config(state=tk.DISABLED)
        self.text_hex_data.config(state=tk.DISABLED)
        self.text_ascii.config(state=tk.DISABLED)
        
        # Scroll to top
        self.text_offset.see(1.0)
        self.text_hex_data.see(1.0)
        self.text_ascii.see(1.0)
        
        # Clear selection after regenerating view
        self.selection_start = None
        self.selection_end = None
        self.update_data_inspector()
        
        # Update status bar
        self.update_status_bar()
    
    def sync_scroll(self, *args):
        """مزامنة التمرير بين الأعمدة الثلاثة"""
        if args:
            # Called from scrollbar
            self.text_offset.yview(*args)
            self.text_hex_data.yview(*args)
            self.text_ascii.yview(*args)
    
    def on_text_scroll(self, *args):
        """تحديث scrollbar عند التمرير"""
        self.hex_scrollbar.set(*args)
        self.sync_scroll('moveto', args[0])
    
    def on_hex_click(self, event):
        """معالجة النقر على hex column"""
        if not self.analyzer or not self.analyzer.data:
            return "break"
        
        # Get click position
        index = self.text_hex_data.index(f"@{event.x},{event.y}")
        line, col = map(int, index.split('.'))
        
        # Calculate byte position
        byte_offset = self.calculate_byte_from_position(line, col)
        if byte_offset is not None:
            self.selection_start = byte_offset
            self.selection_end = byte_offset
            self.highlight_selection()
            self.update_data_inspector()
            self.update_status_bar()
        
        return "break"
    
    def on_hex_drag(self, event):
        """معالجة السحب على hex column"""
        if not self.analyzer or not self.analyzer.data or self.selection_start is None:
            return "break"
        
        # Get current position
        index = self.text_hex_data.index(f"@{event.x},{event.y}")
        line, col = map(int, index.split('.'))
        
        # Calculate byte position
        byte_offset = self.calculate_byte_from_position(line, col)
        if byte_offset is not None:
            self.selection_end = byte_offset
            self.highlight_selection()
            self.update_data_inspector()
            self.update_status_bar()
        
        return "break"
    
    def on_ascii_click(self, event):
        """معالجة النقر على ASCII column"""
        if not self.analyzer or not self.analyzer.data:
            return "break"
        
        # Get click position
        index = self.text_ascii.index(f"@{event.x},{event.y}")
        line, col = map(int, index.split('.'))
        
        # Calculate byte offset (16 bytes per line, col is byte position)
        byte_offset = self.current_offset + (line - 1) * 16 + col
        
        if byte_offset < len(self.analyzer.data):
            self.selection_start = byte_offset
            self.selection_end = byte_offset
            self.highlight_selection()
            self.update_data_inspector()
            self.update_status_bar()
        
        return "break"
    
    def on_ascii_drag(self, event):
        """معالجة السحب على ASCII column"""
        if not self.analyzer or not self.analyzer.data or self.selection_start is None:
            return "break"
        
        # Get current position
        index = self.text_ascii.index(f"@{event.x},{event.y}")
        line, col = map(int, index.split('.'))
        
        # Calculate byte offset
        byte_offset = self.current_offset + (line - 1) * 16 + col
        
        if byte_offset < len(self.analyzer.data):
            self.selection_end = byte_offset
            self.highlight_selection()
            self.update_data_inspector()
            self.update_status_bar()
        
        return "break"
    
    def calculate_byte_from_position(self, line, col):
        """حساب موقع البايت من موقع المؤشر في hex column"""
        grouping = int(self.byte_grouping)
        bytes_per_line = 16
        
        # Layout constants matching display_hex_at_offset
        # Each byte is "XX " (3 chars), but last byte in group has no trailing space
        # So group_width = grouping * 3 - 1
        # Gap between groups = 2
        group_width = grouping * 3 - 1
        gap_width = 2
        
        current_pos = 0
        for group_idx in range(bytes_per_line // grouping):
            # Check if cursor is in this group
            group_end = current_pos + group_width
            
            if col >= current_pos and col < group_end:
                # Find byte within group
                offset_in_group = col - current_pos
                byte_in_group = offset_in_group // 3
                
                byte_index = group_idx * grouping + byte_in_group
                if byte_index < bytes_per_line:
                    byte_offset = self.current_offset + (line - 1) * bytes_per_line + byte_index
                    if byte_offset < len(self.analyzer.data):
                        return byte_offset
                break
            
            current_pos = group_end + gap_width
        
        return None
    
    def highlight_selection(self):
        """تحديد البايتات المحددة"""
        if self.selection_start is None:
            return
        
        # Enable editing temporarily
        self.text_hex_data.config(state=tk.NORMAL)
        self.text_ascii.config(state=tk.NORMAL)
        
        # Remove previous selection
        self.text_hex_data.tag_remove("selection", "1.0", tk.END)
        self.text_ascii.tag_remove("selection", "1.0", tk.END)
        
        # Calculate range
        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end)
        
        # Highlight in both columns
        grouping = int(self.byte_grouping)
        bytes_per_line = 16
        
        # Layout constants matching display_hex_at_offset
        group_width = grouping * 3 - 1
        gap_width = 2
        
        for offset in range(start, end + 1):
            if offset >= len(self.analyzer.data):
                break
            
            # Calculate line and position
            relative_offset = offset - self.current_offset
            line = (relative_offset // bytes_per_line) + 1
            byte_in_line = relative_offset % bytes_per_line
            
            # Hex column position using same formula as display_hex_at_offset
            group_idx = byte_in_line // grouping
            byte_in_group = byte_in_line % grouping
            
            hex_pos = group_idx * (group_width + gap_width) + byte_in_group * 3
            
            hex_start = f"{line}.{hex_pos}"
            hex_end = f"{line}.{hex_pos + 2}"
            
            # ASCII column position
            ascii_start = f"{line}.{byte_in_line}"
            ascii_end = f"{line}.{byte_in_line + 1}"
            
            self.text_hex_data.tag_add("selection", hex_start, hex_end)
            self.text_ascii.tag_add("selection", ascii_start, ascii_end)
        
        # Disable editing
        self.text_hex_data.config(state=tk.DISABLED)
        self.text_ascii.config(state=tk.DISABLED)
    
    def update_data_inspector(self):
        """تحديث لوحة Data Inspector"""
        # Check if there's no valid selection for current view
        if (self.selection_start is None or self.selection_end is None or 
            not self.analyzer or not self.analyzer.data or 
            self.selection_start >= len(self.analyzer.data)):
            # Reset all values
            for key in self.inspector_labels:
                self.inspector_labels[key].config(text="--")
            return
        
        # Get selected bytes
        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end)
        selected_bytes = self.analyzer.data[start:end + 1]
        
        if len(selected_bytes) == 0:
            # Reset all values
            for key in self.inspector_labels:
                self.inspector_labels[key].config(text="--")
            return
        
        # Update values based on available bytes
        try:
            # Single byte values
            if len(selected_bytes) >= 1:
                self.inspector_labels["int8"].config(text=str(struct.unpack('b', selected_bytes[0:1])[0]))
                self.inspector_labels["uint8"].config(text=str(struct.unpack('B', selected_bytes[0:1])[0]))
                self.inspector_labels["binary"].config(text=f"{selected_bytes[0]:08b}")
                self.inspector_labels["decimal"].config(text=str(selected_bytes[0]))
                self.inspector_labels["hex"].config(text=f"0x{selected_bytes[0]:02X}")
            
            # Two byte values
            if len(selected_bytes) >= 2:
                self.inspector_labels["int16_le"].config(text=str(struct.unpack('<h', selected_bytes[0:2])[0]))
                self.inspector_labels["int16_be"].config(text=str(struct.unpack('>h', selected_bytes[0:2])[0]))
            else:
                self.inspector_labels["int16_le"].config(text="--")
                self.inspector_labels["int16_be"].config(text="--")
            
            # Four byte values
            if len(selected_bytes) >= 4:
                self.inspector_labels["int32_le"].config(text=str(struct.unpack('<i', selected_bytes[0:4])[0]))
                self.inspector_labels["int32_be"].config(text=str(struct.unpack('>i', selected_bytes[0:4])[0]))
                self.inspector_labels["float"].config(text=f"{struct.unpack('<f', selected_bytes[0:4])[0]:.6f}")
            else:
                self.inspector_labels["int32_le"].config(text="--")
                self.inspector_labels["int32_be"].config(text="--")
                self.inspector_labels["float"].config(text="--")
            
            # Eight byte values
            if len(selected_bytes) >= 8:
                self.inspector_labels["int64_le"].config(text=str(struct.unpack('<q', selected_bytes[0:8])[0]))
                self.inspector_labels["int64_be"].config(text=str(struct.unpack('>q', selected_bytes[0:8])[0]))
                self.inspector_labels["double"].config(text=f"{struct.unpack('<d', selected_bytes[0:8])[0]:.10f}")
            else:
                self.inspector_labels["int64_le"].config(text="--")
                self.inspector_labels["int64_be"].config(text="--")
                self.inspector_labels["double"].config(text="--")
        
        except Exception as e:
            # Handle any unpacking errors
            pass
    
    def update_status_bar(self):
        """تحديث شريط الحالة"""
        if not self.analyzer or not self.analyzer.data:
            return
        
        # Update offset
        self.status_offset.config(text=f"Offset: 0x{self.current_offset:08X} ({self.current_offset})")
        
        # Update selection
        if self.selection_start is not None and self.selection_end is not None:
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end)
            size = end - start + 1
            self.status_selection.config(
                text=f"Selection: 0x{start:08X} - 0x{end:08X} ({size} bytes)"
            )
            
            # Update current value
            if size == 1:
                byte_val = self.analyzer.data[start]
                self.status_value.config(text=f"Value: 0x{byte_val:02X} ({byte_val})")
            else:
                self.status_value.config(text=f"Value: {size} bytes selected")
        else:
            self.status_selection.config(text="Selection: None")
            self.status_value.config(text="Value: --")
        
        # Update file size
        self.status_size.config(text=f"Size: {len(self.analyzer.data)} bytes")
    
    def change_byte_grouping(self, event):
        """تغيير تجميع البايتات"""
        self.byte_grouping = int(self.grouping_combo.get())
        # Redisplay with new grouping
        self.display_hex_at_offset(self.current_offset)
    
    def search_hex(self):
        """البحث في البيانات"""
        if not self.analyzer or not self.analyzer.data:
            messagebox.showwarning("تحذير", "لم يتم تحليل ملف بعد")
            return
        
        search_str = self.search_entry.get().strip()
        if not search_str:
            messagebox.showwarning("تحذير", "أدخل نصاً للبحث")
            return
        
        try:
            # Try to interpret as hex string
            search_bytes = None
            if all(c in '0123456789ABCDEFabcdef ' for c in search_str):
                # Hex string
                hex_str = search_str.replace(' ', '')
                if len(hex_str) % 2 == 0:
                    search_bytes = bytes.fromhex(hex_str)
            
            # If not hex, treat as ASCII
            if search_bytes is None:
                search_bytes = search_str.encode('utf-8')
            
            # Search from last position or after current offset
            start_pos = max(self.search_last_pos + 1, self.current_offset)
            found_pos = self.analyzer.data.find(search_bytes, start_pos)
            
            # Track if we wrapped around
            wrapped = False
            
            # If not found, wrap around
            if found_pos == -1 and start_pos > 0:
                found_pos = self.analyzer.data.find(search_bytes, 0)
                wrapped = True
            
            if found_pos != -1:
                self.search_last_pos = found_pos
                # Jump to offset
                self.current_offset = (found_pos // 512) * 512  # Align to 512 bytes
                self.display_hex_at_offset(self.current_offset)
                
                # Select found bytes
                self.selection_start = found_pos
                self.selection_end = found_pos + len(search_bytes) - 1
                self.highlight_selection()
                self.update_data_inspector()
                
                # Update status bar to show match position instead of messagebox
                match_info = f"Match found at 0x{found_pos:08X}"
                if wrapped:
                    match_info += " (wrapped)"
                self.status_selection.config(
                    text=f"Selection: 0x{self.selection_start:08X} - 0x{self.selection_end:08X} ({len(search_bytes)} bytes) - {match_info}"
                )
                self.update_status_bar()
            else:
                # Only show messagebox when nothing found after full wrap-around
                self.search_last_pos = 0
                messagebox.showinfo("لم يُعثر", "لم يتم العثور على النتيجة")
        
        except Exception as e:
            messagebox.showerror("خطأ", f"خطأ في البحث: {str(e)}")
    
    def copy_selection(self):
        """نسخ البايتات المحددة"""
        if self.selection_start is None or not self.analyzer or not self.analyzer.data:
            messagebox.showwarning("تحذير", "لا يوجد تحديد")
            return
        
        try:
            # Get selected bytes
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end)
            selected_bytes = self.analyzer.data[start:end + 1]
            
            # Convert to hex string
            hex_str = ' '.join(f'{b:02X}' for b in selected_bytes)
            
            # Copy to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(hex_str)
            
            messagebox.showinfo("نجح", f"تم نسخ {len(selected_bytes)} بايت إلى الحافظة")
        
        except Exception as e:
            messagebox.showerror("خطأ", f"خطأ في النسخ: {str(e)}")
    
    def browse_file(self):
        """ديه الوظيفة اللي بتفتح نافذة اختيار الملف"""
        filepath = filedialog.askopenfilename(
            title="اختر ملف للتحليل",
            filetypes=[
                ("All Files", "*.*"),
                ("Disk Images", "*.001 *.img *.dd"),
                ("Registry Files", "*.dat"),
                ("All Supported", "*.001 *.img *.dd *.dat")
            ]
        )
        
        if filepath:
            self.selected_file.set(filepath)
            # نظهر رسالة في منطقة التقرير
            self.report_text.config(state=tk.NORMAL)
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, f"✅ تم اختيار الملف:\n{filepath}\n\n")
            self.report_text.insert(tk.END, "اضغط على 'بدء التحليل' لبدء الفحص...\n")
            self.report_text.config(state=tk.DISABLED)
    
    def copy_report(self):
        """ديه الوظيفة اللي بنسخ التقرير للحافظة (clipboard)"""
        try:
            # نجيب محتوى التقرير كله
            report_content = self.report_text.get(1.0, tk.END)
            
            # لو التقرير فاضي، ما ننسخش
            if not report_content.strip() or report_content.strip() == "":
                messagebox.showinfo("معلومة", "لا يوجد تقرير للنسخ")
                return
            
            # ننسخ للحافظة
            self.root.clipboard_clear()
            self.root.clipboard_append(report_content)
            self.root.update()  # نتأكد إن النسخ تم
            
            # رسالة تأكيد
            messagebox.showinfo("نجح", "✅ تم نسخ التقرير إلى الحافظة بنجاح!")
            
        except Exception as e:
            messagebox.showerror("خطأ", f"حدث خطأ أثناء النسخ:\n{str(e)}")
    
    def analyze_file(self):
        """ديه الوظيفة اللي بتشغل التحليل"""
        filepath = self.selected_file.get()
        
        # نتأكد إنه اختار ملف
        if not filepath or filepath == "لم يتم اختيار ملف":
            messagebox.showwarning("تحذير", "الرجاء اختيار ملف أولاً!")
            return
        
        # نتأكد إن الملف موجود
        if not os.path.exists(filepath):
            messagebox.showerror("خطأ", f"الملف غير موجود:\n{filepath}")
            return
        
        # Reset selection and data inspector when loading new file
        self.selection_start = None
        self.selection_end = None
        
        # تنظيف جميع التبويبات
        for text_widget in [self.text_mbr, self.text_gpt, self.text_filesystem, 
                           self.text_registry, self.text_encryption, self.text_anomalies, self.text_hex]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, "⏳ جاري التحليل... يرجى الانتظار...\n\n")
            text_widget.update()
        
        try:
            # ننشئ محلل ونشغل التحليل
            self.analyzer = ForensicAnalyzer(filepath)
            
            if not self.analyzer.read_file():
                messagebox.showerror("خطأ", "فشل في قراءة الملف")
                return
            
            file_type = self.analyzer.detect_file_type()
            
            # عرض Hex في البداية
            self.display_hex_at_offset(0, 2048)
            
            # توزيع النتائج على التبويبات
            if file_type == 'MBR':
                mbr_report = self.analyzer.analyze_mbr()
                self.text_mbr.config(state=tk.NORMAL)
                self.text_mbr.delete(1.0, tk.END)
                self.text_mbr.insert(tk.END, mbr_report)
                self.text_mbr.config(state=tk.DISABLED)
                
                # استخراج Anomalies
                self.extract_anomalies(mbr_report)
                
            elif file_type == 'GPT':
                gpt_report = self.analyzer.analyze_gpt()
                self.text_gpt.config(state=tk.NORMAL)
                self.text_gpt.delete(1.0, tk.END)
                self.text_gpt.insert(tk.END, gpt_report)
                self.text_gpt.config(state=tk.DISABLED)
                
                self.extract_anomalies(gpt_report)
                
            elif file_type == 'FAT32':
                fat_report = self.analyzer.analyze_fat32()
                self.text_filesystem.config(state=tk.NORMAL)
                self.text_filesystem.delete(1.0, tk.END)
                self.text_filesystem.insert(tk.END, fat_report)
                self.text_filesystem.config(state=tk.DISABLED)
                
                # تحليل FAT متقدم
                deep_fat = self.analyzer.deep_fat_analysis()
                if deep_fat:
                    self.text_filesystem.config(state=tk.NORMAL)
                    self.text_filesystem.insert(tk.END, "\n\n" + "="*80 + "\n")
                    self.text_filesystem.insert(tk.END, "🔍 Deep FAT Structure Analysis:\n")
                    self.text_filesystem.insert(tk.END, "="*80 + "\n\n")
                    self.text_filesystem.insert(tk.END, deep_fat)
                    self.text_filesystem.config(state=tk.DISABLED)
                
                self.extract_anomalies(fat_report)
                
            elif file_type == 'REGISTRY':
                reg_report = self.analyzer.analyze_registry()
                self.text_registry.config(state=tk.NORMAL)
                self.text_registry.delete(1.0, tk.END)
                self.text_registry.insert(tk.END, reg_report)
                self.text_registry.config(state=tk.DISABLED)
                
                self.extract_anomalies(reg_report)
            
            # Run Encryption Analysis (Always)
            enc_report = self.analyzer.analyze_encryption()
            self.text_encryption.config(state=tk.NORMAL)
            self.text_encryption.delete(1.0, tk.END)
            self.text_encryption.insert(tk.END, enc_report)
            self.text_encryption.config(state=tk.DISABLED)
            
            # Add encryption anomalies if any
            if "CONFIRMED" in enc_report or "SUSPICIOUS" in enc_report:
                self.extract_anomalies(enc_report)
            
            messagebox.showinfo("نجح", "✅ تم التحليل بنجاح!")
            
        except Exception as e:
            error_msg = f"❌ حدث خطأ أثناء التحليل:\n{str(e)}"
            import traceback
            error_msg += "\n\n" + traceback.format_exc()
            for text_widget in [self.text_mbr, self.text_gpt, self.text_filesystem, 
                               self.text_registry, self.text_encryption, self.text_anomalies]:
                text_widget.config(state=tk.NORMAL)
                text_widget.insert(tk.END, error_msg)
                text_widget.config(state=tk.DISABLED)
            messagebox.showerror("خطأ", f"حدث خطأ:\n{str(e)}")
    
    def extract_anomalies(self, report_text):
        """استخراج Anomalies من التقرير"""
        self.text_anomalies.config(state=tk.NORMAL)
        self.text_anomalies.delete(1.0, tk.END)
        
        lines = report_text.split('\n')
        in_anomaly_section = False
        anomaly_lines = []
        
        for line in lines:
            if 'Anomaly' in line or '⚠️' in line or 'Malware' in line or 'Encryption' in line:
                in_anomaly_section = True
                anomaly_lines.append(line)
            elif in_anomaly_section and (line.strip() == '' or line.startswith('=')):
                if line.startswith('='):
                    break
            elif in_anomaly_section:
                anomaly_lines.append(line)
        
        if anomaly_lines:
            self.text_anomalies.insert(tk.END, '\n'.join(anomaly_lines))
        else:
            self.text_anomalies.insert(tk.END, "✅ No anomalies detected")
        
        self.text_anomalies.config(state=tk.DISABLED)
    
    def run(self):
        """نشغل الواجهة"""
        self.root.mainloop()


def main():
    """الدالة الرئيسية - هنا بنبدأ البرنامج"""
    # لو في arguments من سطر الأوامر، نستخدم الوضع القديم
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        
        if not os.path.exists(filepath):
            print(f"❌ Error: File not found: {filepath}")
            sys.exit(1)
        
        analyzer = ForensicAnalyzer(filepath)
        analyzer.generate_report()
    else:
        # لو مفيش arguments، نشغل الواجهة الرسومية
        if GUI_AVAILABLE:
            app = ForensicGUI()
            app.run()
        else:
            print("Usage: python forensic_analyzer.py <file_path>")
            print("\nExample:")
            print("  python forensic_analyzer.py disk_image.001")
            print("  python forensic_analyzer.py MBR_Corrupted_Disk.001")
            print("  python forensic_analyzer.py NTUSER.DAT")
            print("\nNote: For GUI mode, run without arguments (requires tkinter)")
            sys.exit(1)


if __name__ == "__main__":
    main()

