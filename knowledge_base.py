# -*- coding: utf-8 -*-
"""
قاعدة المعرفة للتحليل الجنائي الرقمي - Knowledge Base for Digital Forensics Analysis
"""

KNOWLEDGE_BASE = {
    "MBR": {
        "description": """
        Master Boot Record (MBR) - سجل الإقلاع الرئيسي
        
        [INFO] What is MBR?
        - MBR is the first 512 bytes of the disk
        - Contains critical information for system boot
        - Used in legacy systems with BIOS
        
        [STRUCTURE]
        1. Bootloader Code (0-445 bytes): Initial boot code
        2. Partition Table (446-509 bytes): 4 partitions x 16 bytes each
        3. MBR Signature (510-511 bytes): Magic number 55 AA
        
        [FORENSIC IMPORTANCE]
        - Malware can modify MBR (Bootkits)
        - Signature 55 AA is required for boot - changing it makes system unbootable
        - Can extract hidden or deleted partition information
        """
    },
    
    "GPT": {
        "description": """
        GUID Partition Table (GPT) - جدول البارتشنات GUID
        
        [INFO] What is GPT?
        - Modern replacement for MBR
        - Used with UEFI instead of BIOS
        - Supports disks larger than 2TB
        - Supports more than 4 partitions (up to 128)
        
        [STRUCTURE]
        1. Protective MBR (LBA 0): Protection from legacy tools
        2. Primary GPT Header (LBA 1): Primary disk information
        3. Partition Entry Array (LBA 2-33): Partition information
        4. Partitions Data: Actual data
        5. Backup Partition Entries: Backup copy
        6. Backup GPT Header: Backup header
        
        [FORENSIC IMPORTANCE]
        - Redundancy: Backup copy at end of disk
        - Unique GUID for each partition and disk
        - Can restore GPT from backup copy
        """
    },
    
    "FAT32": {
        "description": """
        File Allocation Table 32 (FAT32) - نظام ملفات FAT32
        
        [INFO] What is FAT32?
        - Simple filesystem compatible with most systems
        - Used in USB drives and small disks
        - Maximum file size: 4GB
        
        [STRUCTURE]
        1. Boot Sector (BPB): Basic system information
        2. Reserved Sectors: Reserved sectors
        3. FAT1: First File Allocation Table
        4. FAT2: Backup copy of FAT1
        5. Data Area: Data region (files and folders)
        
        [FORENSIC IMPORTANCE]
        - Deleted file recovery
        - Hidden files detection
        - Timestamp analysis (Timestomping Detection)
        - Slack Space Analysis
        """
    },
    
    "REGISTRY": {
        "description": """
        Windows Registry Forensics - تحليل سجل Windows
        
        [INFO] What is Registry?
        - Hierarchical database containing Windows settings
        - Stores information about users, programs, and devices
        
        [HIVE TYPES]
        1. SYSTEM: System and device settings
        2. SOFTWARE: Installed programs
        3. SAM: User accounts
        4. NTUSER.DAT: User settings
        5. SECURITY: Security policies
        
        [FORENSIC IMPORTANCE]
        - UserAssist: Programs that were executed
        - Recent Docs: Recently opened files
        - USB Devices: Connected USB devices
        - ShimCache: Executed programs
        - BAM/DAM: Program activity
        """
    }
}


def get_explanation(file_type, topic=None):
    """
    Get detailed explanation for a file type or specific topic
    
    Args:
        file_type: File type (MBR, GPT, FAT32, REGISTRY)
        topic: Specific topic (optional)
    
    Returns:
        str: Detailed explanation
    """
    if file_type not in KNOWLEDGE_BASE:
        return f"[WARNING] No knowledge available for {file_type}"
    
    if topic and topic in KNOWLEDGE_BASE[file_type]:
        return KNOWLEDGE_BASE[file_type][topic]
    
    return KNOWLEDGE_BASE[file_type].get("description", "No description available")


def get_all_topics(file_type):
    """Get all available topics for a specific file type"""
    if file_type not in KNOWLEDGE_BASE:
        return []
    return list(KNOWLEDGE_BASE[file_type].keys())
