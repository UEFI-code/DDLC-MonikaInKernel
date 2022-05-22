copy x64\Debug\MonikaDriver-Win10.sys C:\MonikaDrv.sys
sc create MonikaDrv binPath= "C:\MonikaDrv.sys" type= kernel start= demand