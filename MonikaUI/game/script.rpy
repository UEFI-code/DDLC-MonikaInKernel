init python:
    import ctypes
    from ctypes import *
    MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')
# The script of the game goes in this file.

# Declare characters used by this game. The color argument colorizes the
# name of the character.

define m = Character("Monika")


# The game starts here.

label start:

    # Show a background. This uses a placeholder by default, but you can
    # add a file (named either "bg room.png" or "bg room.jpg") to the
    # images directory to show it.

    scene bg room

    # This shows a character sprite. A placeholder is used, but you can
    # replace it by adding a file named "eileen happy.png" to the images
    # directory.

    show monika happy

    $p = create_string_buffer(16)
    $MonikaDLL.MonikaMsg(p)

    # These display lines of dialogue.

    m "You've created a new Ren'Py game."

    m "Get from my DLL: [p.value]"

    m "Once you add a story, pictures, and music, you can release it to the world!"

    # This ends the game.

    return
