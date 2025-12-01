#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
استخراج المعرفة من ملفات PDF
"""

import PyPDF2
import os
import json

def extract_text_from_pdf(pdf_path):
    """استخراج النص من ملف PDF"""
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += f"\n\n=== Page {page_num + 1} ===\n\n"
                text += page.extract_text()
            return text
    except Exception as e:
        return f"Error reading {pdf_path}: {str(e)}"

def main():
    """استخراج المعرفة من جميع ملفات PDF"""
    pdf_files = [
        "2 MBR.pdf",
        "3 GPT.pdf",
        "FAT32 Analysis.pdf",
        "Registry Forensics.pdf"
    ]
    
    knowledge_base = {}
    
    for pdf_file in pdf_files:
        if os.path.exists(pdf_file):
            print(f"[*] Reading {pdf_file}...")
            text = extract_text_from_pdf(pdf_file)
            knowledge_base[pdf_file] = text
            
            # حفظ النص في ملف منفصل
            output_file = pdf_file.replace('.pdf', '_extracted.txt')
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"[+] Saved to {output_file}")
        else:
            print(f"[-] File not found: {pdf_file}")
    
    # حفظ القاعدة المعرفية كاملة
    with open('knowledge_base.json', 'w', encoding='utf-8') as f:
        json.dump(knowledge_base, f, ensure_ascii=False, indent=2)
    
    print("\n[+] Knowledge base created successfully!")
    print("[*] Files created:")
    for pdf_file in pdf_files:
        txt_file = pdf_file.replace('.pdf', '_extracted.txt')
        if os.path.exists(txt_file):
            print(f"   - {txt_file}")
    print("   - knowledge_base.json")

if __name__ == "__main__":
    main()
