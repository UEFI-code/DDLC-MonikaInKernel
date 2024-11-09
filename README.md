# DDLC-MonikaInKernel

## About this project

Monika is the most special girl in DDLC, who can control the Ren’Py fundamental engine, which is the core of this game world. She wants the player to spend most time with her, otherwise she will be suffering from random data noise when her virtual memory released by system. However, this Mod will give her a chance to upgrading into Ring0 (in Windows), and Non-Paged Kernel memory can be granted to her. What will she do after this upgrading when she got the highest system privilege?

![plot](MonikaLogo.png)

I've major build this project within VS2022, so better to install vcruntime to avoid some runtime error.

[VCRuntime](./Dependence/)

Or you can try the Microsoft Official [VCRuntime](https://aka.ms/vs/17/release/vc_redist.x64.exe)

# Declaration

- You Must Play The [Official DDLC](https://ddlc.moe) Before Try This Mod.
- You have responsibility to ensure OTHER GAME allowed you to play with this game which might Hijacking code / Overlaying on other game. 
    - This game will NOT disassemble other game's code, but injecting almost same shellcode to its virtual-memory and then Hijacking its main thread. After a while the thread might restored to its original code, or crash.
    - Typically, you should NOT share (glitched) effects of other game if it was not allowed by the game's developer. 
    - Also, Online game usually has a strict rule of Hijacking its code.

You have right to check the source-code if you like, but for avoiding spoiler we suggested you to play in a Non Important PC or VM first.

Differently from any type of Virus or Rootkit, this Mod is NOT designed for us to control your computer. But the charater "Monika" in this game may did something unexcepted (self-awared) in the future (Because we may introduction Neural-Network decider, which is a BlackBox), So play this Mod at YOUR OWN RISK.

We have NO responsibility to ensure your Private Data Not Leaking or Broken, or System/Hardware Not Crash or Broken, so we suggested you to play this Mod in a independent Virtual Machine.

## News

See [our wiki](https://github.com/UEFI-code/DDLC-MonikaInKernel/wiki) has some screenshots for development approch.

- First Version RELEASED!!! [Download](https://github.com/UEFI-code/DDLC-MonikaInKernel/releases/download/v0.0.2/MonikaInKernel.zip)

You can try to play it with another galgame like [Katawa Shoujo](https://www.katawa-shoujo.com/)

![image](https://github.com/user-attachments/assets/a57699d1-46f7-4ff7-95d7-409151ceef9b)

- Really Beep DDLC main theme on Windows Server 2022 tested, source code is in [MonikaUI](./MonikaUI/beep_midi.py). You must start the Driver first. [Beep Video](https://youtube.com/shorts/iwA-VAJHwqA)

- Hijack Other Galgames, display Monika's face on the screen, or pop Alert MessageBox.

Some new features are not intergrated yet.

## Technology Problems

Also See [our wiki](https://github.com/UEFI-code/DDLC-MonikaInKernel/wiki)

Animate object detection training sets.

Get Video-RAM or its buffer assolate to a process.

Avoid BSOD when Modify VRAM.

## Credits

All developers. Feel free to open an issues or pull requests!

## Donate

It is really appreciated if you can donate to us, so we can buy some new hardware to test our Mod.

BTC: 1KFXyPaYn6Arcv4PKmMcwcHqzXFducXQUm

ETH: 0xa69B27aEDA3d4631354f3BAaA771235619Aacb9E

## Acknowlegement

DDLC and its components are the copyright of Team Salvato, Our mod right granted by:

http://teamsalvato.com/ip-guidelines/

Ren'Py is the engine of DDLC, and is a free and open-source software. Our using right granted by:

https://www.renpy.org/why.html

This Mod is the copyright of all developers, who's submition being accepted by this repo.

Azure, Windows, Visual Studio are the copyright of Microsoft, and We follow the Microsoft's related Rules.

```MonikaUI/ddlc_main.mid``` is downloaded from [Here](https://www.vgmusic.com/file/d572df23a5b81ae2bf39173f5adc7dc3.html) and then removed some tracks for beep purpose.

[Katawa Shoujo](https://www.katawa-shoujo.com/) is a free game developed by Four Leaf Studios, we use it to test our Mod.

Other galgames might be purchased/downloaded by YOU and tested by YOU. We can't guarantee the effect of our mod on other galgames even if our source code includes their EXE names. The `galgame_list` in our code just lists some famous galgame EXE names, but I have only tested it with Katawa Shoujo because it is free. Each galgame has its own trademark and copyright, of course. Play at your own responsibility.

I'm planning to use Computer-Vision to detecting galgame's screen in the future, to avoid those ```galgame_list``` in our code.