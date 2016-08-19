#!/usr/bin/python

import Tkinter
import tkMessageBox

top = Tkinter.Tk()

def helloCallBack():
	tkMessageBox.showinfo(" Hello Python", "Hello World")
B = Tkinter.Button(top, text="Hello", command = helloCallBack)

B.pack()
# Code to add widgets will go here...
top.mainloop()