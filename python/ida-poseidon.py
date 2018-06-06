import os
#import pefile
import ida_kernwin
from ida_kernwin import Choose


chooser = None


def uint64_t(n):
    """
    Because python uses arbitrary-precision integers, we need to bound it
    to uint64 to match the C implementation.
    """
    return n & 0xffffffffffffffff


def poseidon_hasher(data):
    """
    This is the PoSeidon hasher which is the same for both the dll and
    function name. The dll name version differs by normalizing the name
    first. It ensures it's in the printable range (at least ' ' or 0x20)
    """
    n = 0
    for c in data:
        n += c
        n += n << 10
        n = (uint64_t(n) >> 6) ^ n
    n += n << 3
    n ^= uint64_t(n) >> 11
    n += n << 15
    return uint64_t(n)


def hash_dll_name(name):
    # it ensures character is in the printable range (at least a space)
    # but it doesn't bound it at the upper end though.
    name = [c | ord(' ') if c - ord('A') <= 25 else c for c in map(ord, name)]
    return poseidon_hasher(name)


def hash_function_name(name):
    return poseidon_hasher(map(ord, name))


class chooser_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, thing):
        ida_kernwin.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        sel = []
        for idx in ctx.chooser_selection:
            sel.append(str(idx))
        if self.thing == "import-as-enum":
            # import everything
            dllenum = idc.GetEnum("DllHash")
            if dllenum == 0xffffffff:
                dllenum = idc.AddEnum(0, "DllHash", idaapi.hexflag())

            dlls_added = []
            for dll, func, dllhash, funchash in chooser.items:
                dllhash, funchash = int(dllhash, 16), int(funchash, 16)
                dllname = os.path.splitext(dll)[0]
                enumname = "%s_%s" % (dll, func)
                if dllname not in dlls_added:
                    print("adding dll_%s" % dllname)
                    idc.AddConstEx(dllenum, "dll_%s" % dllname, dllhash & 0xffffffff, -1)
                    dlls_added.append(dllname)
                print("adding %s" % enumname)
                idc.AddConstEx(dllenum, enumname, funchash & 0xffffffff, -1)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ida_kernwin.is_chooser_widget(ctx.widget_type) \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


class PoSeidonChoose(Choose):
    def __init__(self):
        Choose.__init__(self, 'PoSeidon dll and function hashes',
            [["Module Name", 30], ["Function Name", 30], ["Dll Hash", 10], ["Function Hash", 10]])
        self.n = 0
        self.items = self.load_items()
        self.n = len(self.items)
        self.icon = 5

    def OnInit(self):
        print("inited", str(self))
        return True

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

    def OnGetLine(self, n):
        return self.items[n]

    def OnPopup(self, form, popup_handle):
        desc = ida_kernwin.action_desc_t("import-as-enum", "Import as Enum", chooser_handler_t("import-as-enum"))
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

    def show(self):
        return self.Show(False) >= 0

    @staticmethod
    def load_items():
        with open(r'd:\tw-tools\projects\malware-analysis\PoSeidon\python\fn-hash.csv', 'rt') as f:
            # skip first line (heading)
            f.readline()
            return [line.rstrip().split(',') for line in f.readlines()]

    """
    def load_items(self):
        dlls = ["kernel32.dll", "ntdll.dll", "advapi32.dll", "wininet.dll", "crypt32.dll",
                "iphlpapi.dll", "psapi.dll", "userenv.dll", ]
        items = []
        for dll in dlls:
            items += self.load_dll_functions(dll)
        return items
    
    def load_dll_functions(self, dll):
        sys32 = os.path.join(os.environ.get('SystemRoot', r'c:\windows'), 'system32')
        dllhash = hash_dll_name(os.path.join(sys32, dll))
        pe = pefile.PE(dll)
        return [[dll, hash_function_name(e.name.decode('name')), e.name.decode('ascii')]
                for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    """


def calc_hashes():
    global chooser
    chooser = PoSeidonChoose()
    chooser.show()


if __name__ == '__main__':
    calc_hashes()

