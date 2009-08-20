from idautils import *
from idaapi import *
#import idp_hook

"""
It doesn't look like much but this took me way longer than i thought
you will need a patched/updated idapython that supports hooking IDP notifications
"""

def cancel_all_analysis(ea):
    # Probably don't need to cancel ALL of this... but i'm being paranoid and lazy
    autoUnmark(ea, ea + 1, AU_UNK)
    autoUnmark(ea, ea + 1, AU_CODE)
    autoUnmark(ea, ea + 1, AU_WEAK)
    autoUnmark(ea, ea + 1, AU_PROC)
    autoUnmark(ea, ea + 1, AU_TAIL)
    autoUnmark(ea, ea + 1, AU_TRSP)
    autoUnmark(ea, ea + 1, AU_USED)
    autoUnmark(ea, ea + 1, AU_TYPE)
    autoUnmark(ea, ea + 1, AU_LIBF)
    autoUnmark(ea, ea + 1, AU_LBF2)
    autoUnmark(ea, ea + 1, AU_LBF3)
    autoUnmark(ea, ea + 1, AU_CHLB)
    autoUnmark(ea, ea + 1, AU_FINAL)

class Unmark_Auto_Crefs(IDP_Hooks):
    """ add_cref hooker thing """
    def __init__(self):
        IDP_Hooks.__init__(self) # Don't forget!
        self.cancel_these = []
        self.tracking = False

    def get_cancels(self):
        """ get the list of shit  to cancel and clear the list out """
        rv = self.cancel_these
        self.cancel_these = []
        return rv
        
    def track_cancels(self):
        """ track stuff to cancel """
        self.cancel_these = []
        self.tracking = True
        
    def ignore_cancels(self):
        """ stop tracking stuff to cancel """
        self.cancel_these = []
        self.tracking = False

    def add_cref(self, frm, to, type):
        if (type & XREF_USER) == 0:
            # We don't want to actually cancel (return negative) the actual cref
            # Because I *WANT* the crefs in the database for the pretty pictures! (nodes linked together)
            # We just want to make sure that, when the cref is added, that no analysis occurs
            #
            # So the usage scenario is this:
            # install the hook
            # clear the "cancels" array
            # create_insn
            #   -> cref gets called and we add all of them to the "cancels" array
            # go through the cancels array and cancel/unmark them
            # unmark THE CURRENT INSTRUCTION as well (otherwise, after creating the insn, the analyzer
            # will analyze it and try to re-add the cross-refs again, but by this point we are not
            # around to cancel the cross-refs before they get turned into instructions)
            if self.tracking:
                self.cancel_these.append(to)
            return 0
        else:
            # we ignore 'user' cross-refs, under the assumption i may want to add my own while tracking
            return 0

# it's a global so i don't have ot pass it around, and so main() can clear the hook in a finally
# (otherwise you get AV when attempting to close IDA cuz the hook gets pulled out after the script
# runs but IDA things its still there.  then you can't save anything and have to kill idag.exe)
global unmark_auto_crefs
unmark_auto_crefs = None

def create_one_insn(ea):
    length = decode_insn(ea)
    do_unknown_range(ea, length, DOUNK_SIMPLE)

    unmark_auto_crefs.track_cancels()
    try:
        length = create_insn(ea)
        cancels = unmark_auto_crefs.get_cancels()
        cancel_all_analysis(ea) # make sure ida doesn't re-add the crefs after we're done cancelling
        for cea in cancels:
            cancel_all_analysis(cea)
        return length
    finally:
        unmark_auto_crefs.ignore_cancels()
        pass
    
def main():
    ea = get_screen_ea()

    global unmark_auto_crefs
    unmark_auto_crefs = Unmark_Auto_Crefs()
    unmark_auto_crefs.hook()

    try:
        #trace_func(ea)
        create_one_insn(ea)
    finally:
        unmark_auto_crefs.unhook()
        pass

if __name__ == '__main__':
    main()
