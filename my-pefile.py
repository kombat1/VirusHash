import pefile
import sys
import argparse


def exe(file):
	pe = pefile.PE(file)
	if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			print(entry.dll)
			for imp in entry.imports:
				if imp.name != None:
					print("\t",imp.name)
				else:
					print("\ttord(",imp.ordinal,")")
				print("\n")
				exit()

def dll(file):
	pe = pefile.PE(file)
	if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			print(exp.name)

def imphash(file):
	pe = pefile.PE(file)
	print(pe.get_imphash())

def section_hash(file):
	pe = pefile.PE(file)
	for section in pe.sections:
		a = section.Name.decode().replace('\x00','')+"\t"+section.get_hash_md5()
		print(a)
