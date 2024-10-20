import mido
import os
from ctypes import *
import signal
import sys
import time

MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')
MonikaDLL.get_my_driver_handle.restype = c_uint8
status = MonikaDLL.get_my_driver_handle()
if status != 0:
    print("Error in loading driver")
    exit()

# regist ctrl-c handler
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    MonikaDLL.MonikaBeepStop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Function to convert MIDI note number to frequency (Hz)
def midi_note_to_freq(note):
    A4 = 440  # Frequency of A4
    return A4 * (2 ** ((note - 69) / 12))

# Function to play a beep sound for a given MIDI note
def play_beep_for_midi(note, duration_ms):
    frequency = int(midi_note_to_freq(note))  # Convert MIDI note to frequency
    print(f'Playing note {note} at {frequency} Hz for {duration_ms} ms')
    MonikaDLL.MonikaBeepStart(frequency)  # Start beep
    time.sleep(duration_ms / 1000)  # Sleep for duration
    MonikaDLL.MonikaBeepStop()  # Stop beep

# Read MIDI file
def play_midi_beep(file_path):
    mid = mido.MidiFile(file_path)
    tempo = 50000  # Default tempo (microseconds per beat)

    for msg in mid.play():
        if msg.type == 'note_on' and msg.velocity > 0:  # Play note
            duration_ms = int(tempo / 1000)  # Convert tempo to milliseconds
            play_beep_for_midi(msg.note, duration_ms)
        elif msg.type == 'set_tempo':  # Update tempo
            tempo = msg.tempo
    
    MonikaDLL.MonikaBeepStop()  # Stop beep

midi_file = 'ddlc_main.mid'
play_midi_beep(midi_file)