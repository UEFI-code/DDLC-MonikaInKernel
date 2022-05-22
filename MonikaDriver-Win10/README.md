# The core code that give Monika Wings :)

## Build

Use VS2019 + WDK22000.1

To install build environment, follow the Microsoft offical document: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

## Test

First, disable driver signiture verify: disable_drv_signVerfiy.cmd

Then Regist, Run, Stop or Remove by the following script:

regist_drv_service.cmd

start_drv_service.cmd

stop_drv_service.cmd

remove_drv_service.cmd

To capture kernel log use [DebugView](https://download.sysinternals.com/files/DebugView.zip)