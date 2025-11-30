import tkinter as tk
from Files.index import EncryptionApp
def activate():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    activate()