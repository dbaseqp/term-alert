#!/usr/bin/env python
import urwid
from time import sleep
from threading import Thread 

MAX_ALERTS = 20
FRAME_HEADER = "Term-Alert v2.0"
TAB_SIZE = 4

class PopUpDialog(urwid.WidgetWrap):
    """A dialog that appears with nothing but a close button """
    signals = ['close']
    close_message = 'close'
    def __init__(self, title, message):
        self.title = title
        self.set_description(message)

    def set_description(self, message):
        close_button = urwid.Button(PopUpDialog.close_message)
        urwid.connect_signal(close_button, 'click',
            lambda button:self._emit("close"))
        pile = urwid.Pile([urwid.Text(self.title, align='center'), urwid.Text(message), close_button])
        fill = urwid.Filler(pile)
        self.__super.__init__(urwid.AttrWrap(fill, 'popbg'))
        self.message = message

    def get_description(self):
        return self.message

class Alert(urwid.PopUpLauncher):
    count = 1
    def __init__(self, title, message):
        self.id = Alert.count
        title = expand_tab(str(self.id) + '.\t'+ title)
        self.__super.__init__(urwid.Button(title))
        urwid.connect_signal(self.original_widget, 'click',
            lambda button: self.open_pop_up())
        self.pop_up = PopUpDialog('\n'+title+'\n',message+'\n\n')
        self.message = message
        Alert.count += 1

    def create_pop_up(self):
        urwid.connect_signal(self.pop_up, 'close',
            lambda button: self.close_pop_up())
        return self.pop_up

    def get_pop_up_parameters(self):
        colsrows = urwid.raw_display.Screen().get_cols_rows()
        cols = colsrows[0]-4
        rows = max(7, int(len(self.message)/int(cols/2))+1)
        return {'left':0, 'top':1, 'overlay_width':cols, 'overlay_height':rows}

    def set_description(self, message):
        self.pop_up.set_description(message)
        self.message = self.pop_up.get_description()

class TUI(Thread):
    status = False
    animate_alarm = None
    palette = []
    placeholder = urwid.SolidFill()
    alerts = [] 
    lb = None
    frame = None
    content = None
    loop = None

    def __init__(self):
        super(TUI, self).__init__()
        self.daemon = False
        self.cancelled = False 
        
        for i in range(26):
            TUI.alerts.append(Alert('alert ' + str(i+1), 'message'))
        
        self.draw()

    def run(self):
        while not self.cancelled:
            self.update()
            sleep(0.1)

    def cancel(self):
        self.cancelled = True

    def update(self):
        pass

    def handle_input(self, key):
        if key in ('q', 'Q'):
            self.cancel()
            raise urwid.ExitMainLoop()
        elif key in ('c', 'C'):
            TUI.alerts.clear()
            TUI.content[:] = TUI.alerts
            self.change_screen()
        elif key in ('a', 'A'):
            TUI.alerts.append(Alert('new alert', 'exampledescription'*20))
            TUI.content[:] = TUI.alerts
            self.change_screen()
        else:
            if not TUI.status:
                TUI.status = True
                self.update_ui()

    def draw(self):
        TUI.palette = [
        ('popbg', 'white', 'dark blue'),
        ('a_banner', '', '', '', '#ffa', '#60d'),
        ('a_streak', '', '', '', 'g50', '#60a'),
        ('a_inside', '', '', '', 'g38', '#808'),
        ('a_outside', '', '', '', 'g27', '#a06'),
        ('a_bg', '', '', '', 'g7', '#d06'),
        ('c_banner', '', '', '', '#ffa', '#066'),
        ('c_streak', '', '', '', '#066', '#066'),
        ('c_inside', '', '', '', '#076', '#076'),
        ('c_outside', '', '', '', '#0a5', '#0a5'),
        ('c_bg', '', '', '', '#0c5', '#0c5')
        ]
        TUI.content = urwid.SimpleFocusListWalker(TUI.alerts)
        TUI.lb = urwid.ListBox(TUI.content)
        self.change_screen()
        TUI.loop = urwid.MainLoop(
            TUI.frame,
            TUI.palette,
            pop_ups=True, 
            unhandled_input=self.handle_input)
        TUI.loop.screen.set_terminal_properties(colors=256)
        TUI.loop.run()

    def change_screen(self):
        warning =  False if len(TUI.alerts) == 0 else True
        background = urwid.AttrMap(TUI.placeholder, 'a_bg' if warning else 'c_bg' )
        background.original_widget = urwid.Filler(urwid.Pile([]))
        pile = background.base_widget
        div = urwid.Divider()
        outside = urwid.AttrMap(div, 'a_outside' if warning else 'c_outside')
        inside = urwid.AttrMap(div, 'a_inside' if warning else 'c_inside')
        if warning:
            streak = urwid.AttrMap(urwid.BoxAdapter(TUI.lb, height=min(len(TUI.alerts), MAX_ALERTS)), 'a_streak' if warning else 'c_streak')
        else:
            streak = urwid.AttrMap(urwid.Text(('c_banner', u'nothing detected'), align='center'), 'c_streak')
        pile.contents.clear()
        for item in [ outside, inside, streak, inside, outside ]:
            pile.contents.append((item, pile.options()))
        pile.focus_position = 2
        TUI.frame = urwid.Frame(background, header=urwid.Text(FRAME_HEADER))
        if TUI.loop:
            TUI.loop.screen.clear()
            TUI.loop.widget = TUI.frame


    def update_ui(self, loop=None, user_data=None):
        self.change_screen() 
        TUI.animate_alarm = TUI.loop.set_alarm_in(0.1, self.update_ui)

def expand_tab(text: str, width: int = TAB_SIZE):
    width = max(2, width)
    result = []
    for line in text.splitlines():
        try:
            while True:
                i = line.index('\t')
                pad = ' ' * (width - (i % width))
                line = line.replace('\t', pad, 1)
        except ValueError:
            result.append(line)
    return '\n'.join(result)

def main():
    tui = TUI().start()
    TUI.alerts.append(Alert('test', 'test'))

if __name__=='__main__':
    main()
