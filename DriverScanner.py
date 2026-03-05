#!/usr/bin/env python3

import os
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Errore: La libreria 'pefile' non è installata.")
    sys.exit(1)


def scan_drivers(path):

    if not os.path.exists(path):
        print(f"Errore: Il percorso '{path}' non esiste.")
        return []
    
    if not os.path.isdir(path):
        print(f"Errore: '{path}' non è una directory.")
        return []
    
    try:
        drivers = []
        for filename in os.listdir(path):
            if filename.lower().endswith('.sys'):
                full_path = os.path.join(path, filename)
                drivers.append(full_path)
        
        return drivers
    except PermissionError:
        print(f"Errore: Permessi insufficienti per accedere a '{path}'.")
        return []


def get_imported_libraries(driver_path):

    try:
        pe = pefile.PE(driver_path)
        imports_dict = {}
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                lib_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"Ordinal({imp.ordinal})"
                    functions.append(func_name)
                
                imports_dict[lib_name] = functions
        
        return imports_dict
    except Exception as e:
        print(f"   Errore nella lettura di {driver_path}: {e}")
        return {}


def main():
    if len(sys.argv) < 2:
        print("Utilizzo: python DriverScanner.py <path>")
        sys.exit(1)
    
    path = sys.argv[1]
    drivers = scan_drivers(path)
    
    if drivers:
        print(f"\nDriver .sys che importano ntoskrnl.exe con ZwTerminateProcess:\n")
        found_count = 0
        
        for driver in drivers:

            imports_dict = get_imported_libraries(driver)
            
            ntoskrnl_lib = None
            for lib in imports_dict.keys():
                if 'ntoskrnl' in lib.lower():
                    ntoskrnl_lib = lib
                    break
            
            if ntoskrnl_lib:
                functions = imports_dict[ntoskrnl_lib]
                if any('ZwTerminateProcess' in func for func in functions):
                    found_count += 1
                    
                    size_bytes = os.path.getsize(driver)
                    
                    print(f"{found_count}. {os.path.basename(driver)} {size_bytes} bytes")
                                       
                    print(f"   Libreria: {ntoskrnl_lib}")
                    print(f"   Funzioni importate da {ntoskrnl_lib}:")
                    
                    for func in functions:
                        if 'ZwTerminateProcess' in func:
                            print(f"      - {func}")
                    print("----------")
        
        if found_count == 0:
            print(f"Nessun driver che importa ntoskrnl.exe con ZwTerminateProcess trovato in '{path}'.")
        else:
            print(f"Totale: {found_count}")
    else:
        print(f"Nessun file driver .sys trovato in '{path}'.")


if __name__ == "__main__":
    main()
