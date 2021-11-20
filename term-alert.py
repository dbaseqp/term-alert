import os
import urwid
import time
import magic

theList = {}
for root, dirs, files in os.walk("/", topdown=True): #intial indexing of everything except /proc (funky directory)
    if "proc" in dirs:
        dirs.remove("proc")
    if "run" in dirs:
        dirs.remove("run")
    if "mnt" in dirs:
        dirs.remove("mnt")
    if "lib" in dirs:
        dirs.remove("lib")
    for name in files:
        x = os.path.join(root, name)
        if theList.__contains__(x) == False:
            theList[x] = 1
        else:
            theList[x] += 1

def signal_alert():
# Signals used for alerts
    signal = False
    message = 'ALERT!'
    theCheckList = {}
    for root, dirs, files in os.walk("/", topdown=True): #comparison indexing
        if "proc" in dirs:
            dirs.remove("proc")
        if "run" in dirs:
            dirs.remove("run")
        if "mnt" in dirs:
            dirs.remove("mnt")
        if "lib" in dirs:
            dirs.remove("lib")
        for name in files:
            x = os.path.join(root, name)
            if theCheckList.__contains__(x) == False:
                theCheckList[x] = 1
            else:
                theCheckList[x] += 1  
    if theCheckList != theList:
        differenceDict = dict(set(theCheckList.items()) - set(theList.items())) #remove all original array items from array from new check to see whats up
        for key in differenceDict:
            try:
                if "ELF" in magic.from_file(key) or "PHP" in magic.from_file(key) or "script" in magic.from_file(key): #are any of the new items elfs
                    signal = True
                    message += '\n' + key + ' exists'
            except:
                continue
    if signal:
        return(True, message)
    return (False, 'nothing detected')

class Alert:
    def __init__(self):
        self.loop = None
        self.animate_alarm = None
        self.placeholder = urwid.SolidFill()
        self.palette = []

    def update_screen(self):
        result = signal_alert()
        if result[0]:
            self.alert_screen(result[1])
        else:
            self.calm_screen(result[1])
        self.loop.screen.clear()
            
    def handle_input(self, key):
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        else:
            self.update()

    def alert_screen(self, message):
        self.palette = [
            ('banner', '', '', '', '#ffa', '#60d'),
            ('streak', '', '', '', 'g50', '#60a'),
            ('inside', '', '', '', 'g38', '#808'),
            ('outside', '', '', '', 'g27', '#a06'),
            ('bg', '', '', '', 'g7', '#d06'),]
        self.txt.set_text(('banner', message))
        if self.loop:
            self.loop.screen.register_palette(self.palette)
            self.loop.widget = urwid.AttrMap(self.placeholder, 'bg')
            self.loop.widget.original_widget = urwid.Filler(urwid.Pile([]))
            div = urwid.Divider()
            outside = urwid.AttrMap(div, 'outside')
            inside = urwid.AttrMap(div, 'inside')
            streak = urwid.AttrMap(self.txt, 'streak')
            pile = self.loop.widget.base_widget # .base_widget skips the decorations
            for item in [outside, inside, streak, inside, outside]:
                pile.contents.append((item, pile.options()))

    def calm_screen(self, message):
        self.palette = [
            ('banner', '', '', '', '#ffa', '#066'),
            ('streak', '', '', '', '#066', '#066'),
            ('inside', '', '', '', '#076', '#076'),
            ('outside', '', '', '', '#0a5', '#0a5'),
            ('bg', '', '', '', '#0c5', '#0c5'),]
        self.txt.set_text(('banner', message))
        if self.loop:
            self.loop.screen.register_palette(self.palette)
            self.loop.widget = urwid.AttrMap(self.placeholder, 'bg')
            self.loop.widget.original_widget = urwid.Filler(urwid.Pile([]))
            div = urwid.Divider()
            outside = urwid.AttrMap(div, 'outside')
            inside = urwid.AttrMap(div, 'inside')
            streak = urwid.AttrMap(self.txt, 'streak')
            pile = self.loop.widget.base_widget # .base_widget skips the decorations
            for item in [outside, inside, streak, inside, outside]:
                pile.contents.append((item, pile.options()))

    def draw(self):
    # The main method for starting the Alarm. 
        self.txt = urwid.Text(('banner', u'Press any button...'), align='center')
        self.loop = urwid.MainLoop(self.placeholder, self.palette, unhandled_input=self.handle_input)
        
        self.loop.screen.set_terminal_properties(colors=256)
        self.loop.widget = urwid.AttrMap(self.placeholder, 'bg')
        self.loop.widget.original_widget = urwid.Filler(urwid.Pile([]))
        div = urwid.Divider()
        outside = urwid.AttrMap(div, 'outside')
        inside = urwid.AttrMap(div, 'inside')
        streak = urwid.AttrMap(self.txt, 'streak')
        pile = self.loop.widget.base_widget # .base_widget skips the decorations
        pile.contents.clear()
        for item in [outside, inside, streak, inside, outside]:
            pile.contents.append((item, pile.options()))
        self.loop.run()

    def update(self, loop=None, user_data=None):
        self.update_screen()
        self.animate_alarm = self.loop.set_alarm_in(0.1, self.update)

def main():
    Alert().draw()

if '__main__'==__name__:
    main()
    

