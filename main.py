import os
import sys
import pefile
import qdarkstyle
from struct import *
from pydbg import *
from pydbg.defines import *
from PySide.QtGui import *
from PySide.QtCore import *

class TestListView(QListWidget):

    fileDropped = Signal(list)

    def __init__(self, type):
        super(TestListView, self).__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls:
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls:
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls:
            event.accept()
            links = []
            for url in event.mimeData().urls():
                links.append(str(url.toLocalFile()))
            self.fileDropped.emit(links)
        else:
            event.ignore()

class DongPacker(QMainWindow):
    def __init__(self):
        super(DongPacker, self).__init__()
        self.view = TestListView(self)
        self.view.fileDropped.connect(self.drdr)
        self.setCentralWidget(self.view)

        self.setStyleSheet("background-image: url(test.jpg);")
        self.setWindowTitle("Dong_Unpacker!!")
        self.setWindowIcon(QIcon('icon.ico'))
        self.resize(266, 189)
        self.show()

    def drdr(self, l):
        if os.path.exists(l[0]):
            self.view.clear()
            QListWidgetItem(l[0], self.view)
            self.unpack(l[0])

    def signature(self, dbg):
        sig = dbg.read_process_memory(self.ep+6, 2)
        if sig.encode("hex") == "8dbe":
            QListWidgetItem("[*] Packing with UPX!!", self.view)
        else:
            QListWidgetItem("[*] Signature not found", self.view)

    def entry_point(self, dbg):
        self.API(self.dbg)
        disasm = dbg.disasm(dbg.exception_address)
        esp = dbg.context.Esp
        dbg.bp_set_hw(esp, 4, HW_ACCESS, handler=self.OEP, restore=False)
        return DBG_CONTINUE

    def OEP(self, dbg):
        disasm = dbg.disasm(dbg.exception_address)

        if disasm.startswith("jmp"):
            self.num = True
            dbg.single_step(True)
        else:
            dbg.single_step(True)
        return DBG_CONTINUE

    def single_step(self, dbg):
        disasm = dbg.disasm(dbg.exception_address)

        if 0x70000000 < int(dbg.exception_address):
            pass
        elif disasm.startswith("jmp"):
            self.num = True
            dbg.single_step(True)
        elif self.num:
            dbg.bp_del_all()
            text = "[*] Find OEP: " + hex(dbg.exception_address)
            item = QListWidgetItem(text, self.view)
            # item.setBackground(QColor("red"))
            self.upx(self.dbg)
        else:
            dbg.single_step(True)
        return DBG_CONTINUE


    def API(self, dbg):
        self.loadlibA = dbg.func_resolve("kernel32.dll","LoadLibraryA")
        self.getprocaddr = dbg.func_resolve("kernel32.dll","GetProcAddress")
        dbg.bp_set(self.loadlibA, handler=self.LoadLibraryA, restore=True)
        dbg.bp_set(self.getprocaddr, handler=self.GetProcessAddress, restore=True)
        return DBG_CONTINUE

    def GetProcessAddress(self, dbg):
        esp = dbg.context.Esp
        api_addr = unpack("<I", dbg.read_process_memory(esp+8, 4))[0]
        api_name = dbg.get_ascii_string(dbg.read_process_memory(api_addr, 30))

        if self.switch == True:
            self.API_Names.append([])
            self.switch = False

        INDEX = len(self.API_Names) - 1

        if len(api_name) % 2 == 0:
            self.API_Names[INDEX].append(api_name)
        else:
            self.API_Names[INDEX].append(api_name+"\x00")
        return DBG_CONTINUE
        
    def LoadLibraryA(self, dbg):
        self.switch = True
        esp = dbg.context.Esp
        ebx = dbg.context.Ebx

        dll_addr = unpack("<I", dbg.read_process_memory(esp+4, 4))[0]
        dll_name = dbg.read_process_memory(dll_addr, 20)
        dll_name = dbg.get_ascii_string(dll_name)

        if dll_name.lower().endswith("dll"):
            INDEX = len(self.DLL_Names)
            self.DLL_Names.append([])
            self.DLL_Names[INDEX].append(dll_name+'\x00')
            self.DLL_Names[INDEX].append(ebx)

            if ebx > self.IAT_DLL_OFFSET[0]:
                self.IAT_DLL_OFFSET[0] = ebx
                self.IAT_DLL_OFFSET[1] = INDEX
        else:
            pass

        self.API(self.dbg)
        return DBG_CONTINUE


    def upx(self, dbg):
        o = open("dump.exe", "wb")

        ImageBase = self.pe.OPTIONAL_HEADER.ImageBase
        base = int(ImageBase + self.pe.sections[1].VirtualAddress)

        SizeOfDOSHeader = unpack("<I", dbg.read_process_memory(ImageBase+0x3c, 4))[0]
        DOS_Header = dbg.read_process_memory(ImageBase, SizeOfDOSHeader)
        text = dbg.read_process_memory(ImageBase, 0x300)
        add = text.encode('hex').find("50450000")
        DOS_Header = dbg.read_process_memory(ImageBase, (add/2))
        QListWidgetItem("[*] DOS Header!!", self.view)

        base1 = int(ImageBase + self.pe.sections[1].VirtualAddress)
        length = int(self.pe.sections[1].Misc_VirtualSize)
        NT = dbg.read_process_memory(base1, length)
        add = NT.encode('hex').find("50450000")
        NT_Header = dbg.read_process_memory(base1+(add/2), 0xf8)
        NumOfSection = unpack("<H", NT_Header[6:8])[0]
        SizeOfPEHeader = unpack("<I", NT_Header[0x54:0x58])[0]
        QListWidgetItem("[*] NT Header!!", self.view)

        Section = dbg.read_process_memory(base1+(add/2)+0xf8, 0x28 * NumOfSection)
        padding = SizeOfPEHeader-(len(DOS_Header) + len(NT_Header) + len(Section))
        QListWidgetItem("[*] Section Header!!", self.view)

        DataOfSection = ''
        for x in range(NumOfSection):
            index = x * 0x28
            VV_Addr = unpack("<I", Section[index+12:index+16])[0]
            V_Addr = ImageBase + VV_Addr
            V_Size = unpack("<I", Section[index+16:index+20])[0]
            Section_Name = Section[index:index+6]
            Section_Name = dbg.get_ascii_string(Section_Name)
            # IAT RECOVERY
            if Section_Name == ".idata":
                IAT = "\x00" * V_Size
                NumOfAPI = [len(x) for x in self.API_Names]
                NumOfDLL = len(self.DLL_Names)

                QListWidgetItem("[*] found DLL: "+ str(NumOfDLL), self.view)
                QListWidgetItem("[*] found API: "+ str(sum(NumOfAPI)-NumOfDLL), self.view)

                self.IAT_DLL_OFFSET = self.IAT_DLL_OFFSET[0] - (V_Addr - (NumOfAPI[self.IAT_DLL_OFFSET[1]] + 1) * 4)

                # IMPORT DLL Names
                IMPORT_DLL_Names = ""
                IMPORT_DLL_Names += "".join(["".join(self.DLL_Names[x][0]) for x in range(NumOfDLL)])
                IMPORT_DLL_Names += "\x00"

                # IMPORT Hints/Names
                IMPORT_Hints = "\x00\x00"
                IMPORT_Hints += "\x00\x00".join(["\x00\x00".join(y) for y in self.API_Names])

                # LenOfImport
                LenOfImport = len(IMPORT_DLL_Names) + len(IMPORT_Hints)

                # IAT Rebuilding
                IAT = IAT[:self.IAT_DLL_OFFSET] + IMPORT_DLL_Names + IMPORT_Hints + IAT[self.IAT_DLL_OFFSET+LenOfImport:]
                self.IAT_DLL_OFFSET += VV_Addr            
                # IMPORT_Directory_Talbe 
                for x in range(NumOfDLL):
                    IAT = IAT[:(0x14*x)+0xc] + pack("<I", self.IAT_DLL_OFFSET) + pack("<I", self.DLL_Names[x][1]-ImageBase) + IAT[(0x14*x)+0x14:]
                    self.IAT_DLL_OFFSET += len(self.DLL_Names[x][0])

                API_RVA = self.IAT_DLL_OFFSET + 1

                # IMPORT_Address_Table 
                for x in range(NumOfDLL):
                    IMPORT_Address_Table = ""
                    for y in range(NumOfAPI[x]):
                        IMPORT_Address_Table += pack("<I", API_RVA)
                        API_RVA += len(self.API_Names[x][y]) + 2
                    INDEX = self.DLL_Names[x][1] - V_Addr
                    INDEX_ = INDEX + len(IMPORT_Address_Table) + 4
                    IAT = IAT[:INDEX] + IMPORT_Address_Table + "\x00\x00\x00\x00" + IAT[INDEX_:]
                
                DataOfSection += IAT

            elif Section_Name == ".rsrc":
                for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for entry in rsrc.directory.entries:
                        pass
                rva = (entry.directory.entries[0].data.struct.OffsetToData)
                size = (entry.directory.entries[0].data.struct.Size)
                va = self.pe.sections[2].VirtualAddress
                address = rva-va+size
                rsrc_data = dbg.read_process_memory(V_Addr, V_Size)
                DataOfSection += dbg.read_process_memory(va+ImageBase, address) + rsrc_data[address:]
            else:
                DataOfSection += dbg.read_process_memory(V_Addr, V_Size)
        
        o.write(DOS_Header+NT_Header+Section+'\x00'*padding+DataOfSection)
        o.close()
        QListWidgetItem("[!] Success!!", self.view)
        return DBG_CONTINUE

    def unpack(self, name):
        QListWidgetItem("[!] File Loading Success!!", self.view)
        self.num = False
        self.switch = True
        self.DLL_Names = []
        self.API_Names = []
        self.IAT_DLL_OFFSET = [0, 0]
        self.pe = pefile.PE(name)
        self.ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.ep += self.pe.OPTIONAL_HEADER.ImageBase
        self.dbg = pydbg()
        self.dbg.set_callback(EXCEPTION_SINGLE_STEP, self.single_step)
        self.dbg.load(name)
        self.signature(self.dbg)
        self.dbg.bp_set(self.ep+1, handler=self.entry_point, restore=False)
        self.dbg.run()

app = QApplication(sys.argv)
app.setStyleSheet(qdarkstyle.load_stylesheet())
main = DongPacker()
sys.exit(app.exec_())